/*
 * Stat structure implementation for packet sniffer
 * Written by alnyan (Mark Polyakov)
 * Test task for Sirin Software
 *
 */

#include "sniff.h"
#include <stdlib.h>

void sn_stat_init(struct sn_stat *s, size_t sz) {
    s->size = 0;
    s->cap = sz;
    s->saddrs = calloc(sizeof(uint32_t), sz);
    s->counts = calloc(sizeof(uint32_t), sz);
}

void sn_stat_insert(struct sn_stat *s, uint32_t saddr, uint32_t count) {
    /* Insertion to an empty array */
    if (s->size == 0) {
        s->saddrs[0] = saddr;
        s->counts[0] = count;
        s->size = 1;
        return;
    }

    /* Find index to insert after */
    ssize_t idx;
    for (idx = 0; idx < s->size; ++idx) {
        if (s->saddrs[idx] > saddr) {
            break;
        }
    }

    /* Extend arrays if needed */
    if (s->size + 1 > s->cap) {
        s->cap += SN_STAT_BLOCK_SZ;
        s->saddrs = realloc(s->saddrs, s->cap * sizeof(uint32_t));
        s->counts = realloc(s->counts, s->cap * sizeof(uint32_t));
    }

    /* Perform insertion */
    for (size_t i = s->size; i > idx; --i) {
        s->saddrs[i] = s->saddrs[i - 1];
        s->counts[i] = s->saddrs[i - 1];
    }

    s->saddrs[idx] = saddr;
    s->counts[idx] = count;

    ++s->size;
}

ssize_t sn_stat_lookup_idx(const struct sn_stat *s, uint32_t saddr) {
    ssize_t start, mid, end;

    start = 0;
    end = s->size;
    mid = (start + end) / 2;

    while (start <= end) {
        if (s->saddrs[mid] < saddr) {
            start = mid + 1;
        } else if (s->saddrs[mid] > saddr) {
            end = mid - 1;
        } else {
            return mid;
        }

        mid = (start + end) / 2;
    }

    return -1;
}

uint32_t sn_stat_inc(struct sn_stat *s, uint32_t saddr) {
    ssize_t idx = sn_stat_lookup_idx(s, saddr);

    if (idx != -1) {
        return ++s->counts[idx];
    } else {
        sn_stat_insert(s, saddr, 1);

        return 1;
    }
}

struct sn_stat *sn_stat_create(void) {
    struct sn_stat *res = (struct sn_stat *) malloc(sizeof(struct sn_stat));
    sn_stat_init(res, SN_STAT_BLOCK_SZ);
    return res;
}

void sn_stat_free(struct sn_stat *s) {
    free(s->saddrs);
    free(s->counts);
    free(s);
}

void sn_stat_write(const struct sn_stat *s, FILE *f) {
    fwrite(&s->size, sizeof(size_t), 1, f);
    fwrite(&s->cap, sizeof(size_t), 1, f);
    fwrite(s->saddrs, sizeof(uint32_t), s->cap, f);
    fwrite(s->counts, sizeof(uint32_t), s->cap, f);
}

int sn_stat_read(struct sn_stat *s, FILE *f) {
    if (fread(&s->size, sizeof(size_t), 1, f) != 1 ||
        fread(&s->cap, sizeof(size_t), 1, f) != 1) {
        return -1;
    }

    s->saddrs = calloc(s->cap, sizeof(uint32_t));
    s->counts = calloc(s->cap, sizeof(uint32_t));

    if (fread(s->saddrs, sizeof(uint32_t), s->cap, f) != s->cap ||
        fread(s->counts, sizeof(uint32_t), s->cap, f) != s->cap) {
        return -1;
    }

    return 0;
}
