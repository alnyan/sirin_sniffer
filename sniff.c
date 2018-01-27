/*
 * Sniffer main code (+ daemon part)
 * Written by alnyan (Mark Polyakov)
 * Test task for Sirin Software
 *
 */

#include "sniff.h"

#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/stat.h>
#include <linux/ip.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <net/if.h>
#include <stdio.h>

/* pcap handle */
static pcap_t *sn_pcap_handle = NULL;

/* Current stats context and stats file */
static const char *sn_stats_filename = NULL;
static struct sn_stat *sn_stats_context = NULL;

/* Updates count (if greater than SN_THRESHOLD, flush is triggered) */
static uint32_t sn_delta = 0;

int sn_is_interface_active(const struct ifaddrs *iface) {
    /* Check if an interface is active:
     * 1. It is not an loopback device (like 127.0.0.1)
     * 2. It is up
     * 3. It is running (has allocated resources)
     * 4. It has an interface address
     * 5. The address is IPv4
     */
    return !(iface->ifa_flags & IFF_LOOPBACK) &&
            (iface->ifa_flags & IFF_UP) &&
            (iface->ifa_flags & IFF_RUNNING) &&
            iface->ifa_addr &&
            iface->ifa_addr->sa_family == AF_INET;
}

/* See:
 *  man 3 getifaddrs */
int sn_active_interface(struct sn_iface *iface) {
    struct ifaddrs *ifaddrss = NULL;

    if (getifaddrs(&ifaddrss) == -1) {
        perror("failed to get interface list");
        return -1;
    }

    /* Iterate over linked list of network interfaces */
    for (struct ifaddrs *it = ifaddrss; it; it = it->ifa_next) {
        /* Select first active interface and clone info */
        if (sn_is_interface_active(it)) {
            /* Clone interface name */
            iface->name = strdup(it->ifa_name);

            /* Clone interface address */
            struct sockaddr_in *inaddr = (struct sockaddr_in *) it->ifa_addr;
            iface->addr = ntohl(inaddr->sin_addr.s_addr);

            /* Free resources and return success */
            freeifaddrs(ifaddrss);

            return 0;
        }
    }

    /* Free resource allocated by getifaddrs */
    freeifaddrs(ifaddrss);

    return -1;
}

int sn_interface_by_name(const char *name, struct sn_iface *iface) {
    struct ifaddrs *ifaddrss = NULL;

    if (getifaddrs(&ifaddrss) == -1) {
        perror("failed to get interface list");
        return -1;
    }

    /* Iterate over network interface and find matching IPv4-capable interface */
    for (struct ifaddrs *it = ifaddrss; it; it = it->ifa_next) {
        /* Check if name matches and it is capable of IPv4 networking */
        if (strcmp(it->ifa_name, name) == 0
                && it->ifa_addr
                && it->ifa_addr->sa_family == AF_INET) {
            /* Clone interface name */
            iface->name = strdup(it->ifa_name);

            /* Clone interface address */
            struct sockaddr_in *inaddr = (struct sockaddr_in *) it->ifa_addr;
            iface->addr = ntohl(inaddr->sin_addr.s_addr);

            /* Free resources and return success */
            freeifaddrs(ifaddrss);

            return 0;
        }
    }

    /* Free resource allocated by getifaddrs */
    freeifaddrs(ifaddrss);

    return -1;
}

/* Flushes stats to a file on a disk */
static void sn_flush_stats() {
    syslog(LOG_INFO, "Flushing stats");

    /* Write data */
    FILE *f = fopen(sn_stats_filename, "w");
    sn_stat_write(sn_stats_context, f);
    fclose(f);
}

/* Signal handler for SIGINT and SIGUSR1 */
void sn_signal_handler(int signum) {
    switch (signum) {
        /* SIGTERM - termination is requested */
        case SIGTERM:
            syslog(LOG_INFO, "SIGTERM received, stopping");

            sn_flush_stats();

            pcap_breakloop(sn_pcap_handle);
            break;
        /* SIGUSR1 - flush is requested (e.g. CLI request) */
        case SIGUSR1:
            syslog(LOG_INFO, "External flush requested (SIGUSR1)");

            sn_flush_stats();
            break;
        /* SIGUSR2 - reset stats */
        case SIGUSR2:
            syslog(LOG_INFO, "Resetting stats for current interface");

            sn_stat_free(sn_stats_context);
            sn_stats_context = sn_stat_create();

            break;
    }
}

/* Increases packet count for specified ipv4 addr and interface */
static void sn_log_packet(const char *iname, uint32_t saddr) {
    syslog(LOG_INFO, "Packet: %d.%d.%d.%d",
            (saddr & 0xFF000000) >> 24,
            (saddr & 0xFF0000) >> 16,
            (saddr & 0xFF00) >> 8,
            saddr & 0xFF);

    /* Increase packet counter */
    sn_stat_inc(sn_stats_context, saddr);

    ++sn_delta;

    /* Flush output if threshold is reached */
    if (sn_delta >= SN_THRESHOLD) {
        sn_flush_stats();
        sn_delta = 0;
    }
}

/* Logs stats for incoming packets */
void sn_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    uint32_t size  = h->len;

    /* Get Ethernet header pointer */
    struct ethhdr *ethernet_header = (struct ethhdr *) bytes;
    /* Ethernet header is followed by an IP header */
    struct iphdr *ip_header = (struct iphdr *) (bytes + sizeof(struct ethhdr));

    /* Packet source address */
    uint32_t src_addr = ntohl(ip_header->saddr);
    uint32_t dst_addr = ntohl(ip_header->daddr);

    /* The interface which is used */
    const struct sn_iface *iface = (const struct sn_iface *) user;

    /* If destination address matches interface address, log the packet */
    if (dst_addr == iface->addr) {
        sn_log_packet(iface->name, src_addr);
    }
}

/* Sniffer daemon main code */
int sn_sniffer_main(const struct sn_iface *iface) {
    /* Create logs directory if it does not exist */
    mkdir(SN_FILENAME_PREFIX, 0600);

    /* Create filename for output */
    {
        /* FIXME: possible leak here */
        char *filename = malloc(strlen(SN_FILENAME_PREFIX) + strlen(iface->name) + 1);
        strcpy(filename, SN_FILENAME_PREFIX);
        strcat(filename, iface->name);

        sn_stats_filename = filename;

        syslog(LOG_INFO, "Stats will be stored in `%s'", filename);
    }

    /* Create pid file */
    {
        FILE *pf = fopen(SN_PID_FILENAME, "w");
        pid_t p = getpid();
        fwrite(&p, sizeof(pid_t), 1, pf);
        fclose(pf);
    }

    /* Try to read existing stats file, if it does not exist, create new stats object */
    {
        FILE *f = fopen(sn_stats_filename, "r");

        if (!f) {
            syslog(LOG_INFO, "No stats found for interface `%s', starting new file\n", iface->name);

            sn_stats_context = sn_stat_create();
        } else {
            sn_stats_context = (struct sn_stat *) malloc(sizeof(struct sn_stat));

            /* Delete file and create new stats if file is invalid */
            if (sn_stat_read(sn_stats_context, f) == -1) {
                remove(sn_stats_filename);

                free(sn_stats_context);

                sn_stats_context = sn_stat_create();
            }

            fclose(f);
        }
    }

    /* Bind signals */
    signal(SIGTERM, sn_signal_handler);
    signal(SIGUSR1, sn_signal_handler);
    signal(SIGUSR2, sn_signal_handler);

    char p_errbuf[PCAP_ERRBUF_SIZE];

    /* Create pcap context (and make interface enter promiscuous mode) */
    sn_pcap_handle = pcap_open_live(iface->name, 65536, 1, 0, p_errbuf);

    if (sn_pcap_handle) {
        syslog(LOG_INFO, "Successfully opened pcap handle");
    } else {
        syslog(LOG_ERR, "pcap handle opening failed: %s\n", p_errbuf);
        return EXIT_FAILURE;
    }

    /* Start listening for packets */
    int res = pcap_loop(sn_pcap_handle, -1, sn_packet_handler, (u_char *) iface);

    syslog(LOG_INFO, "pcap_loop() returned %d\n", res);

    pcap_close(sn_pcap_handle);

    /* Remove pid file */
    remove(SN_PID_FILENAME);

    return EXIT_SUCCESS;
}
