/* Guess most modern compilers support this, don't they? */
#pragma once

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Time to wait for daemon to stop */
#define SN_STOP_DELAY       350000 /* 350ms. */
/* Time to wait for daemon to store data */
#define SN_FLUSH_DELAY      250000 /* 250ms. */
/* Stat structure array granularity */
#define SN_STAT_BLOCK_SZ    32
/* Filename where PID of daemon is stored */
#define SN_PID_FILENAME     "/var/run/sniff.pid"
/* Flush output every SN_THRESHOLD packets */
#define SN_THRESHOLD        16
/* Used to get full path for log file */
#define SN_FILENAME_PREFIX  "/var/log/sniff/"

struct sn_iface {
    uint32_t addr;      /* HOST REPRESENTATION (use htonl with this) of ipv4 address */
    const char *name;   /* Interface name */
};

/* Structure used to store stats */
struct sn_stat {
    size_t size, cap;
    uint32_t *saddrs;
    uint32_t *counts;
};

/* Structure functions */
struct sn_stat *sn_stat_create(void);
void sn_stat_free(struct sn_stat *s);
void sn_stat_init(struct sn_stat *s, size_t sz);
ssize_t sn_stat_lookup_idx(const struct sn_stat *s, uint32_t saddr);
uint32_t sn_stat_inc(struct sn_stat *s, uint32_t saddr);
void sn_stat_insert(struct sn_stat *s, uint32_t saddr, uint32_t count);
void sn_stat_write(const struct sn_stat *s, FILE *f);
int sn_stat_read(struct sn_stat *s, FILE *f);

/* Sniffer functions */
int sn_interface_by_name(const char *name, struct sn_iface *res);
int sn_active_interface(struct sn_iface *iface);
int sn_sniffer_main(const struct sn_iface *iface);

