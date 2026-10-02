/* DBDPI - DPI desync tool for Windows (WinDivert based).
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef DBDPI_H
#define DBDPI_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define DBDPI_NAME    "Dice Bypass DPI"
#define DBDPI_VERSION "0.1.0"

#define MAX_HOST          256
#define MAX_PORTS         16
#define MAX_SPLIT_POS     8
#define MAX_PACKET        WINDIVERT_MTU_MAX

/* ---------------------------------------------------------------- logging */
enum { LOG_ERR = 0, LOG_INFO = 1, LOG_DEBUG = 2 };

void log_init(const char *path, int level);
void log_close(void);
void log_msg(int level, const char *fmt, ...);

/* ------------------------------------------------------------- host lists */
typedef struct hostlist {
    char **items;           /* reversed domains, sorted for bsearch */
    size_t n;
    size_t cap;
    char  *path;            /* file path (for hot reload) */
    uint64_t mtime;         /* last known modification time */
} hostlist_t;

int  hostlist_load(hostlist_t *hl, const char *path);
bool hostlist_match(const hostlist_t *hl, const char *host);
bool hostlist_reload_if_changed(hostlist_t *hl);
void hostlist_free(hostlist_t *hl);

/* ---------------------------------------------------------------- conntrack */
typedef struct conn {
    uint8_t  family;            /* 4 / 6 */
    uint8_t  src[16];
    uint8_t  dst[16];
    uint16_t sport, dport;
    uint32_t first_seq;         /* client seq of first data segment */
    bool     desync_done;       /* strategy applied (or decided to pass) */
    bool     passthrough;       /* decided: never touch this conn */
    char     host[MAX_HOST];
    int      autottl_hops;      /* -1 unknown */
    uint64_t last_ms;
    struct conn *next;
} conn_t;

void      conntrack_init(void);
conn_t   *conntrack_get(const uint8_t *src, uint16_t sport,
                        const uint8_t *dst, uint16_t dport, uint8_t family);
conn_t   *conntrack_get_or_add(const uint8_t *src, uint16_t sport,
                               const uint8_t *dst, uint16_t dport, uint8_t family);
void      conntrack_sweep(void);

/* ------------------------------------------------------------------ TLS */
typedef struct {
    bool is_client_hello;
    int  sni_off;               /* payload offset of server name, -1 if none */
    int  sni_ext_off;           /* payload offset of SNI extension header, -1 */
    int  hello_end;             /* offset just past the ClientHello */
    char sni[MAX_HOST];
} tls_info_t;

bool tls_parse_client_hello(const uint8_t *p, size_t len, tls_info_t *ti);

/* ------------------------------------------------------------------ HTTP */
typedef struct {
    bool is_request;
    int  method_end_off;        /* offset of the space right after method */
    int  host_off, host_len;    /* Host header value */
    char host[MAX_HOST];
} http_info_t;

bool http_parse_request(const uint8_t *p, size_t len, http_info_t *hi);

/* --------------------------------------------------------------- fakegen */
/* Returns malloc'd fake payload, sets *out_len. Returns NULL on failure. */
uint8_t *fakegen_tls(const char *sni, size_t *out_len);
uint8_t *fakegen_http(const char *host, size_t *out_len);
/* Loads fake payload from file: raw binary, or plain-hex text if it looks so */
uint8_t *fakegen_load(const char *path, size_t *out_len);

/* ---------------------------------------------------------------- desync */
typedef enum {
    DESYNC_NONE = 0,
    DESYNC_SPLIT,           /* one cut position */
    DESYNC_MULTISPLIT,      /* several cut positions */
    DESYNC_DISORDER,        /* multisplit, segments sent in reverse order */
    DESYNC_FAKE,            /* fake(s) then original packet untouched */
    DESYNC_FAKEDSPLIT,      /* per-segment fake duplicates + multisplit */
} desync_mode_t;

typedef enum {
    FOOL_NONE       = 0,
    FOOL_BADSUM     = 1 << 0,
    FOOL_BADSEQ     = 1 << 1,
    FOOL_TTL        = 1 << 2,
    FOOL_DATANOACK  = 1 << 3,
} fooling_t;

typedef enum {
    SP_MARK_NONE = 0,
    SP_METHOD,                  /* end of HTTP method */
    SP_HOST,                    /* start of host value (HTTP Host / TLS SNI) */
    SP_ENDHOST,                 /* end of host value */
    SP_MIDSLD,                  /* middle of second-level domain */
    SP_SNI,                     /* TLS: start of SNI value */
    SP_SNIEXT,                  /* TLS: start of SNI extension */
} split_marker_t;

typedef struct {
    bool is_marker;
    int  value;                 /* numeric offset when !is_marker */
    split_marker_t marker;
} split_pos_t;

typedef struct {
    desync_mode_t mode;
    split_pos_t   split_pos[MAX_SPLIT_POS];
    int           split_pos_n;
    fooling_t     fooling;
    int           fake_repeats;     /* extra copies of each fake, default 1 */
    int           ttl;              /* fixed fake ttl, 0 = off */
    bool          autottl;          /* derive ttl from path length */
    int           autottl_delta, autottl_min, autottl_max;
    int           badseq_delta;     /* seq offset for badseq fakes, <=0 */
    bool          fake_from_file;   /* fake_tls provided */
    char          *fake_tls_path;
    char          *fake_http_path;
    bool          fake_gen;         /* built-in browser-like ClientHello */
    /* HTTP tricks (same-length only) */
    bool hostcase;                  /* shuffle case of "Host" */
    bool hosttab;                   /* replace space after "Host:" with \t */
    bool methodeol;                 /* prepend \r\n via seqovl */
    uint16_t wsize;                 /* rewrite window in outbound SYN, 0 = off */
    uint32_t max_payload;           /* skip segments bigger than this */
} profile_t;

/* Builds the list of packets to inject instead of the original one.
 * pkt: original packet buffer (will not be modified).
 * addr: address of the captured packet; the generated packets get their
 *       checksums recomputed and the address's "checksum valid" bits set, so
 *       the packets must be injected with this same address (otherwise the
 *       stack may recalculate checksums and undo deliberate badsum fakes).
 * Returns number of packets malloc'd into *out (caller frees each), or -1
 * on failure (caller must reinject the original). */
int desync_apply(const profile_t *prof, const uint8_t *pkt, size_t len,
                 WINDIVERT_ADDRESS *addr, conn_t *cn,
                 const tls_info_t *ti, const http_info_t *hi,
                 uint8_t ***out, size_t **out_lens);

/* ------------------------------------------------------------------ main */
typedef struct {
    uint16_t ports[MAX_PORTS];
    int      ports_n;
    char     *hostlist_path;
    char     *hostlist_exclude_path;
    hostlist_t hostlist, hostlist_exclude;
    profile_t  prof;
    int      log_level;
    char     *log_path;
    bool     dry_run;           /* log desync decisions without injecting */
    int      timeout_sec;       /* auto-exit after N seconds, 0 = off */
} config_t;

/* runtime statistics (updated from divert loop) */
typedef struct {
    volatile LONG64 pkt_total;
    volatile LONG64 pkt_desync;
    volatile LONG64 pkt_passthrough;
    volatile LONG64 pkt_hostlist_miss;
} stats_t;

extern config_t g_cfg;
extern stats_t  g_stats;

int  config_parse(int argc, char **argv);   /* returns 0 ok, >0 exit code, -1 help shown */
void config_defaults(void);

/* Splits a command line in place (quotes are honored, whitespace between
 * tokens becomes NUL). argv[0] is a dummy program name, so the result can be
 * fed to config_parse() as-is. */
char **tokenize_args(char *line, int *argc_out);

int  divert_run(void);                      /* blocking WinDivert loop */
void divert_shutdown(void);                 /* request loop stop (any thread) */

int  service_run_main(const char *args_file);  /* --service-run */
int  selftest(void);

#endif /* DBDPI_H */
