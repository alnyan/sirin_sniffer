/*
 *  Sniffer control interface (CLI)
 *  Written by alnyan (Mark Polyakov)
 *  Test task for Sirin Software
 *
 */

#include "sniff.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <assert.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>

#define SN_HELP     "--help"
#define SN_START    "start"
#define SN_STAT     "stat"
#define SN_STOP     "stop"
#define SN_SHOW     "show"
#define SN_RESET    "reset"
#define SN_SELECT   "select"

static const char *sn_usage_str =
    "Usage: sniffcon <command/--help> ...\n"
    "Available command list:\n"
    "\t* start [iface] - starts the daemon on the current interface (or [iface], if specified)\n"
    "\t* stop - kills the daemon process\n"
    "\t* show [ip] count - shows count of received packets for an IPv4-address [ip]\n"
    "\t* select iface [iface] - switches interface being sniffed to [iface]\n"
    "\t* stat [iface] - prints stats for packets on [iface] (or globally, if omitted)\n"
    "\t* reset - resets packet stats\n"
    "\t* --help - prints this message\n";

void sn_usage(FILE *s) {
    fputs(sn_usage_str, s);
}

int sn_daemon_start(const char *iname, uint32_t iaddr) {
    pid_t p = fork();

    switch (p) {
    case 0:
        /* In child */
        /* Close default streams (syslog will be used instead) */
        freopen("/dev/null", "a", stdout);
        freopen("/dev/null", "a", stderr);
        freopen("/dev/null", "r", stdin);

        /* Init syslog */
        openlog("Sirin Sniffer", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Starting up on interface `%s'", iname);

        /* Create struct sn_iface again (in child) */
        struct sn_iface iface;
        iface.name = iname;
        iface.addr = iaddr;

        /* Run sniffer and store exit code */
        int res = sn_sniffer_main(&iface);

        /* Exit */
        syslog(LOG_INFO, "Stopping");
        closelog();
        exit(res);
    default:
        /* In parent: do nothing */
        return 0;
    case -1:
        perror("fork() failed");
        return -1;
    }
}

static int sn_stat(const char *iname) {
    if (!iname) {
        /* List and print stats from all /var/log/sniff/ files */
        DIR *d = opendir(SN_FILENAME_PREFIX);

        if (!d) {
            perror("Failed to list sniffing stats");
            return EXIT_FAILURE;
        }

        /* Iterate over logs */
        struct dirent *d_ent;

        while (d_ent = readdir(d)) {
            if (d_ent->d_name[0] != '.') {
                /* Each directory entry corresponds to interface name */
                const char *iface = d_ent->d_name;
                sn_stat(iface);
            }
        }

        closedir(d);

        return EXIT_SUCCESS;
    }

    printf("Showing stats for interface `%s'\n", iname);

    /* Allocate stats object */
    struct sn_stat stats;

    /* Create filename for log file */
    char *filename = malloc(strlen(SN_FILENAME_PREFIX) + strlen(iname) + 1);
    strcpy(filename, SN_FILENAME_PREFIX);
    strcat(filename, iname);

    /* Read it */
    FILE *f = fopen(filename, "r");

    if (!f || sn_stat_read(&stats, f) != 0) {
        perror("Failed to read stats");
        return EXIT_FAILURE;
    }

    fclose(f);

    free(filename);

    /* Just to make sure */
    assert(stats.size <= stats.cap);

    /* Print stats */
    for (size_t i = 0; i < stats.size; ++i) {
        printf("\t* %u.%u.%u.%u: %u packet%s",
                (stats.saddrs[i] & 0xFF000000) >> 24,
                (stats.saddrs[i] & 0xFF0000) >> 16,
                (stats.saddrs[i] & 0xFF00) >> 8,
                stats.saddrs[i] & 0xFF,
                stats.counts[i],
                stats.counts[i] != 1 ? "s\n" : "\n"); /* Simple pluralization (may be incorrect) */
    }


    return EXIT_SUCCESS;
}

static int sn_start(const char *iname) {
    struct sn_iface iface;

    /* Check if daemon is already running (and finish with an error in such case) */
    /* Enclose it in a scope so that d_stat is freed */
    {
        struct stat d_stat;
        /* stat() returns non-error code: file exists */
        if (stat(SN_PID_FILENAME, &d_stat) != -1) {
            fprintf(stderr, "Sirin Sniffer is already running\n");
            return EXIT_FAILURE;
        }
    }

    /* No interface name specified, try to get active interface */
    if (!iname) {
        /* Obtain an interface name to start sniffing from */
        if (sn_active_interface(&iface) == -1) {
            fprintf(stderr, "Failed to obtain active interface\n");
            return EXIT_FAILURE;
        }
    } else {
        /* Interface name is explicitly specified, try to get more info */
        if (sn_interface_by_name(iname, &iface) == -1) {
            fprintf(stderr, "Failed to obtain interface information\n");
            return EXIT_FAILURE;
        }
    }

    return sn_daemon_start(iface.name, iface.addr);
}

static int sn_stop(void) {
    /* Read daemon pid from file and send a SIGTERM */
    pid_t pid;

    FILE *pf = fopen(SN_PID_FILENAME, "r");
    if (!pf) {
        perror("Failed to read daemon pid");
        return EXIT_FAILURE;
    }
    fread(&pid, sizeof(pid_t), 1, pf);
    fclose(pf);

    kill(pid, SIGTERM);

    return EXIT_SUCCESS;
}

static int sn_select(const char *iface) {
    printf("Switching to `%s'\n", iface);
    /* Pretty straightforward: stop current daemon and restart it on a different interface */
    if (sn_stop() == EXIT_FAILURE) {
        /* Daemon was not running */
        fprintf(stderr, "Failed to stop daemon. Was it running?\n");
        return EXIT_FAILURE;
    }

    /* Wait for daemon to stop */
    usleep(SN_STOP_DELAY);

    return sn_start(iface);
}

static uint32_t sn_iface_packet_count(uint32_t saddr, const char *iface) {
    /* Get address stats for a particular interface */
    /* Allocate stats object */
    struct sn_stat stats;

    /* Create filename for log file */
    char *filename = malloc(strlen(SN_FILENAME_PREFIX) + strlen(iface) + 1);
    strcpy(filename, SN_FILENAME_PREFIX);
    strcat(filename, iface);

    /* Read it */
    FILE *f = fopen(filename, "r");

    if (!f || sn_stat_read(&stats, f) != 0) {
        perror("Failed to read stats");
        return 0;
    }

    fclose(f);
    free(filename);

    /* Lookup particular address */
    ssize_t idx = sn_stat_lookup_idx(&stats, saddr);

    if (idx == -1) {
        return 0;
    }

    uint32_t c = stats.counts[idx];

    /* Dispose stats object */
    free(stats.saddrs);
    free(stats.counts);

    return c;
}

static int sn_show(const char *addr) {
    /* Convert address string to host integer representation */
    uint32_t saddr;

    {
        struct in_addr iaddr;

        /* Perform IPv4 address form conversion */
        if (inet_pton(AF_INET, addr, &iaddr) != 1) {
            perror("Invalid IPv4 address");
            return EXIT_FAILURE;
        }

        /* Convert address to host form */
        saddr = ntohl(iaddr.s_addr);
    }

    /* Read all log files and look "addr" up */
    DIR *d = opendir(SN_FILENAME_PREFIX);

    if (!d) {
        perror("Failed to list sniffing stats");
        return EXIT_FAILURE;
    }

    /* Total count of packets */
    uint32_t total = 0;
    /* Iterate over logs */
    struct dirent *d_ent;

    while (d_ent = readdir(d)) {
        if (d_ent->d_name[0] != '.') {
            /* Each directory entry corresponds to interface name */
            const char *iface = d_ent->d_name;
            uint32_t c = sn_iface_packet_count(saddr, iface);

            /* If interface log has a record for such address */
            if (c != 0) {
                printf("On interface `%s': %u\n", iface, c);
                total += c;
            }
        }
    }

    printf("Total: %u\n", total);

    closedir(d);

    return EXIT_SUCCESS;
}

static int sn_reset(void) {
    /* Removes all log files and resets daemon stats by sending SIGUSR2 */
    /* Iterate over logs */
    DIR *d = opendir(SN_FILENAME_PREFIX);

    if (!d) {
        perror("Failed to list sniffing stats");
        return EXIT_FAILURE;
    }

    struct dirent *d_ent;

    while (d_ent = readdir(d)) {
        if (d_ent->d_name[0] != '.') {
            const char *iface = d_ent->d_name;
            /* Create filename for log file */
            char *filename = malloc(strlen(SN_FILENAME_PREFIX) + strlen(iface) + 1);
            strcpy(filename, SN_FILENAME_PREFIX);
            strcat(filename, iface);

            printf("Removing `%s'\n", filename);
            remove(filename);

            free(filename);
        }
    }

    /* Send SIGUSR2 to daemon (if it is running) */
    {
        pid_t pid;

        FILE *pf = fopen(SN_PID_FILENAME, "r");
        if (pf) {
            fread(&pid, sizeof(pid_t), 1, pf);
            fclose(pf);

            kill(pid, SIGUSR2);
        }
    }
}

int main(int argc, char **argv) {
    /* Check if any command is specified */
    if (argc < 2) {
        fprintf(stderr, "%s: no command specified\n", argv[0]);
        sn_usage(stderr);
        return EXIT_FAILURE;
    }

    /* Command (start/stop/etc.) */
    const char *cmd = argv[1];

    /* Prints help */
    if (!strcmp(SN_HELP, cmd)) {
        sn_usage(stdout);
        return EXIT_SUCCESS;
    }

    /* Looks up stats for an address */
    if (!strcmp(SN_SHOW, cmd)) {
        /* If arguments do not match specified format, exit */
        if (argc != 4 || strcmp(argv[3], "count")) {
            sn_usage(stderr);
            return EXIT_FAILURE;
        }

        /* Send SIGUSR1 to daemon to flush data */
        {
            pid_t pid;

            FILE *pf = fopen(SN_PID_FILENAME, "r");
            if (pf) {
                fread(&pid, sizeof(pid_t), 1, pf);
                fclose(pf);

                kill(pid, SIGUSR1);
            } else {
                printf("Sirin Sniffer does not seem to be running, showing saved stats\n");
            }
        }

        /* Wait for daemon to flush data */
        usleep(SN_FLUSH_DELAY);

        return sn_show(argv[2]);
    }

    /* Prints stats for interface */
    if (!strcmp(SN_STAT, cmd)) {
        /* Send SIGUSR1 to daemon to flush data */
        {
            pid_t pid;

            FILE *pf = fopen(SN_PID_FILENAME, "r");
            if (pf) {
                fread(&pid, sizeof(pid_t), 1, pf);
                fclose(pf);

                kill(pid, SIGUSR1);
            } else {
                printf("Sirin Sniffer does not seem to be running, showing saved stats\n");
            }
        }

        /* Wait for daemon to flush data */
        usleep(SN_FLUSH_DELAY);

        return sn_stat(argc == 2 ? NULL : argv[2]);
    }

    /* Starts daemon */
    if (!strcmp(SN_START, cmd)) {
        return sn_start(argc == 2 ? NULL : argv[2]);
    }

    /* Stops daemon by sending SIGTERM */
    if (!strcmp(SN_STOP, cmd)) {
        return sn_stop();
    }

    /* Switches to a different interface */
    if (!strcmp(SN_SELECT, cmd)) {
        if (argc != 3) {
            sn_usage(stderr);
            return EXIT_FAILURE;
        }

        return sn_select(argv[2]);
    }

    /* Resets stats */
    if (!strcmp(SN_RESET, cmd)) {
        return sn_reset();
    }

    /* Could not match any available command */
    fprintf(stderr, "%s: invalid command `%s'\n", argv[0], cmd);
    sn_usage(stderr);

    return EXIT_FAILURE;
}
