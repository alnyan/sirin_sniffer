/*
 * Daemon launcher for Sirin Sniffer
 * Written by alnyan (Mark Polyakov)
 * Test task for Sirin Software
 *
 */

#include "sniff.h"

#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

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

        printf("Starting on interface `%s'\n", iface.name);
    } else {
        /* Interface name is explicitly specified, try to get more info */
        if (sn_interface_by_name(iname, &iface) == -1) {
            fprintf(stderr, "Failed to obtain interface information\n");
            return EXIT_FAILURE;
        }
    }

    return sn_daemon_start(iface.name, iface.addr);
}

int main(int argc, char **argv) {
    /* Check root privileges */
    if (geteuid() != 0) {
        fprintf(stderr, "Sirin Sniffer must be run with root privileges\n");
        return EXIT_FAILURE;
    }

    if (argc == 1) {
        /* No interface name specified */
        return sn_start(NULL);
    } else if (argc == 2) {
        /* Interface name is specified explicitly */
        return sn_start(argv[1]);
    } else {
        /* Invalid argument count */
        fprintf(stderr, "Usage: %s [iface]\n", argv[0]);
        return EXIT_FAILURE;
    }
}
