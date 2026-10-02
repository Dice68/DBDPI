/* DBDPI - lightweight TCP connection tracking */
#include "dbdpi.h"

#define CT_BUCKETS 16384
#define CT_TIMEOUT_MS (120 * 1000)

static conn_t *table[CT_BUCKETS];
static uint32_t inserts = 0;
static CRITICAL_SECTION ct_lock;
static int ct_lock_init = 0;

static uint64_t now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

static uint32_t hash_tuple(const uint8_t *src, uint16_t sport,
                           const uint8_t *dst, uint16_t dport, uint8_t family)
{
    uint32_t h = 2166136261u;
    size_t alen = (family == 6) ? 16 : 4;
    size_t i;
    for (i = 0; i < alen; i++) { h ^= src[i]; h *= 16777619u; }
    h ^= sport & 0xFF;       h *= 16777619u;
    h ^= (sport >> 8) & 0xFF; h *= 16777619u;
    for (i = 0; i < alen; i++) { h ^= dst[i]; h *= 16777619u; }
    h ^= dport & 0xFF;        h *= 16777619u;
    h ^= (dport >> 8) & 0xFF; h *= 16777619u;
    h ^= family;              h *= 16777619u;
    return h & (CT_BUCKETS - 1);
}

static bool addr_eq(const uint8_t *a, const uint8_t *b, uint8_t family)
{
    return memcmp(a, b, (family == 6) ? 16 : 4) == 0;
}

void conntrack_init(void)
{
    memset(table, 0, sizeof(table));
    inserts = 0;
    if (!ct_lock_init) { InitializeCriticalSection(&ct_lock); ct_lock_init = 1; }
}

/* internal lookup, caller must hold ct_lock */
static conn_t *ct_find(const uint8_t *src, uint16_t sport,
                        const uint8_t *dst, uint16_t dport, uint8_t family)
{
    uint32_t b = hash_tuple(src, sport, dst, dport, family);
    conn_t *c;
    for (c = table[b]; c; c = c->next)
        if (c->family == family && c->sport == sport && c->dport == dport &&
            addr_eq(c->src, src, family) && addr_eq(c->dst, dst, family))
            return c;
    return NULL;
}

conn_t *conntrack_get(const uint8_t *src, uint16_t sport,
                      const uint8_t *dst, uint16_t dport, uint8_t family)
{
    conn_t *c;
    EnterCriticalSection(&ct_lock);
    c = ct_find(src, sport, dst, dport, family);
    LeaveCriticalSection(&ct_lock);
    return c;
}

conn_t *conntrack_get_or_add(const uint8_t *src, uint16_t sport,
                             const uint8_t *dst, uint16_t dport, uint8_t family)
{
    uint32_t b;
    conn_t *c;

    EnterCriticalSection(&ct_lock);
    c = ct_find(src, sport, dst, dport, family);
    if (c)
    {
        c->last_ms = now_ms();
        LeaveCriticalSection(&ct_lock);
        return c;
    }
    c = calloc(1, sizeof(*c));
    if (!c)
    {
        LeaveCriticalSection(&ct_lock);
        return NULL;
    }
    c->family = family;
    memcpy(c->src, src, (family == 6) ? 16 : 4);
    memcpy(c->dst, dst, (family == 6) ? 16 : 4);
    c->sport = sport;
    c->dport = dport;
    c->autottl_hops = -1;
    c->last_ms = now_ms();

    b = hash_tuple(src, sport, dst, dport, family);
    c->next = table[b];
    table[b] = c;
    inserts++;
    LeaveCriticalSection(&ct_lock);

    if (inserts % 8192 == 0)
        conntrack_sweep();
    return c;
}

void conntrack_sweep(void)
{
    int i;
    uint64_t cutoff = now_ms() - CT_TIMEOUT_MS;
    EnterCriticalSection(&ct_lock);
    for (i = 0; i < CT_BUCKETS; i++)
    {
        conn_t **pp = &table[i];
        while (*pp)
        {
            if ((*pp)->last_ms < cutoff)
            {
                conn_t *dead = *pp;
                *pp = dead->next;
                free(dead);
            }
            else
                pp = &(*pp)->next;
        }
    }
    LeaveCriticalSection(&ct_lock);
}
