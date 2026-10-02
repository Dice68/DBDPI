/* DBDPI - fake packet payload generation:
 * built-in Chrome-like TLS ClientHello (with padding, like real browsers send),
 * fake HTTP request, and loading fakes from files (raw or hex). */
#include "dbdpi.h"

#include <time.h>

static void rand_bytes(uint8_t *p, size_t n)
{
    size_t i;
    static bool seeded = false;
    if (!seeded) { srand((unsigned)(GetTickCount64() ^ GetCurrentProcessId())); seeded = true; }
    for (i = 0; i < n; i++)
        p[i] = (uint8_t)(rand() & 0xFF);
}

/* ---------------------------------------------------------------- TLS fake */
#define FAKE_BUF 4096

typedef struct { uint8_t b[FAKE_BUF]; size_t n; } buf_t;

static bool buf_put(buf_t *x, const void *p, size_t n)
{
    if (x->n + n > sizeof(x->b))
        return false;
    memcpy(x->b + x->n, p, n);
    x->n += n;
    return true;
}
static bool buf_put16(buf_t *x, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    return buf_put(x, t, 2);
}
static bool buf_put8(buf_t *x, uint8_t v) { return buf_put(x, &v, 1); }

/* one extension: type + length + data */
static bool ext_begin(buf_t *x, uint16_t type) { return buf_put16(x, type); }

static const uint8_t CIPHERS[] = {
    0x13,0x01, 0x13,0x02, 0x13,0x03,          /* TLS 1.3 suites */
    0xc0,0x2b, 0xc0,0x2f, 0xc0,0x2c, 0xc0,0x30, /* ECDHE ECDSA/AES */
    0xcc,0xa9, 0xcc,0xa8,                     /* ECDHE chacha */
    0xc0,0x13, 0xc0,0x14,                     /* ECDHE RSA AES */
    0x00,0x9c, 0x00,0x9d, 0x00,0x2f, 0x00,0x35, /* plain RSA */
    0x00,0x0a
};

uint8_t *fakegen_tls(const char *sni, size_t *out_len)
{
    buf_t x;
    size_t sni_len, hs_len, pad;
    uint8_t rnd[32];
    size_t p_ver, p_hslen, p_extlen;

    memset(&x, 0, sizeof(x));
    sni_len = sni ? strlen(sni) : 0;
    if (sni_len == 0 || sni_len > 253)
        sni = "www.google.com", sni_len = 14;

    /* record header with placeholders */
    p_ver = x.n;  buf_put(&x, "\x16\x03\x01\x00\x00", 5);
    p_hslen = x.n; buf_put(&x, "\x01\x00\x00\x00", 4);

    buf_put(&x, "\x03\x03", 2);               /* client version TLS 1.2 */
    rand_bytes(rnd, 32); buf_put(&x, rnd, 32);
    buf_put8(&x, 32);                         /* session id: 32 bytes (Chrome compat) */
    rand_bytes(rnd, 32); buf_put(&x, rnd, 32);
    buf_put16(&x, (uint16_t)sizeof(CIPHERS));
    buf_put(&x, CIPHERS, sizeof(CIPHERS));
    buf_put8(&x, 1); buf_put8(&x, 0);         /* null compression */
    p_extlen = x.n; buf_put16(&x, 0);          /* extensions length placeholder */

    /* --- extensions --- */
    /* server_name */
    ext_begin(&x, 0x0000);
    buf_put16(&x, (uint16_t)(sni_len + 5));
    buf_put16(&x, (uint16_t)(sni_len + 3));
    buf_put8(&x, 0);
    buf_put16(&x, (uint16_t)sni_len);
    buf_put(&x, sni, sni_len);

    /* extended_master_secret */
    ext_begin(&x, 0x0017); buf_put16(&x, 0);
    /* renegotiation_info */
    ext_begin(&x, 0xff01); buf_put16(&x, 1); buf_put8(&x, 0);
    /* supported_groups: x25519, secp256r1, secp384r1 */
    ext_begin(&x, 0x000a); buf_put16(&x, 6);
    buf_put16(&x, 0x001d); buf_put16(&x, 0x0017); buf_put16(&x, 0x001e);
    /* ec_point_formats: uncompressed */
    ext_begin(&x, 0x000b); buf_put16(&x, 2); buf_put8(&x, 1); buf_put8(&x, 0);
    /* session_ticket */
    ext_begin(&x, 0x0023); buf_put16(&x, 0);
    /* alpn: h2, http/1.1 (2-byte protocol list length + entries) */
    ext_begin(&x, 0x0010); buf_put16(&x, 14);
    buf_put16(&x, 12);
    buf_put8(&x, 2);  buf_put(&x, "h2", 2);
    buf_put8(&x, 8);  buf_put(&x, "http/1.1", 8);
    /* status_request: ocsp, empty responder list/extensions */
    ext_begin(&x, 0x0005); buf_put16(&x, 5);
    buf_put8(&x, 1); buf_put16(&x, 0); buf_put16(&x, 0);
    /* signature_algorithms */
    ext_begin(&x, 0x000d); buf_put16(&x, 18);
    buf_put16(&x, 0x0403); buf_put16(&x, 0x0804); buf_put16(&x, 0x0401);
    buf_put16(&x, 0x0503); buf_put16(&x, 0x0805); buf_put16(&x, 0x0501);
    buf_put16(&x, 0x0806); buf_put16(&x, 0x0601); buf_put16(&x, 0x0807);
    /* signed_cert_timestamps */
    ext_begin(&x, 0x0012); buf_put16(&x, 0);
    /* key_share: x25519 32 bytes */
    ext_begin(&x, 0x0033); buf_put16(&x, 36);
    buf_put16(&x, 0x001d); buf_put16(&x, 32);
    rand_bytes(rnd, 32); buf_put(&x, rnd, 32);
    /* psk_key_exchange_modes: psk_dhe_ke */
    ext_begin(&x, 0x002d); buf_put16(&x, 2); buf_put8(&x, 1); buf_put8(&x, 1);
    /* supported_versions: TLS 1.3, TLS 1.2 */
    ext_begin(&x, 0x002b); buf_put16(&x, 4); buf_put16(&x, 0x0304); buf_put16(&x, 0x0303);

    /* padding up to a Chrome-like 512-byte handshake body */
    hs_len = x.n - p_hslen - 4;
    if (hs_len < 512)
    {
        pad = 512 - hs_len;                    /* ext: type+len+data */
        if (pad >= 4)
        {
            ext_begin(&x, 0x0015);
            buf_put16(&x, (uint16_t)(pad - 4));
            { size_t z; for (z = 0; z < pad - 4; z++) buf_put8(&x, 0); }
        }
    }

    /* fix up lengths */
    {
        uint16_t ext_all = (uint16_t)(x.n - p_extlen - 2);
        uint32_t hs = (uint32_t)(x.n - p_hslen - 4);
        uint16_t rec = (uint16_t)(x.n - p_ver - 5);
        x.b[p_extlen]     = (uint8_t)(ext_all >> 8);
        x.b[p_extlen + 1] = (uint8_t)ext_all;
        x.b[p_hslen + 1]  = (uint8_t)(hs >> 16);
        x.b[p_hslen + 2]  = (uint8_t)(hs >> 8);
        x.b[p_hslen + 3]  = (uint8_t)hs;
        x.b[p_ver + 3]    = (uint8_t)(rec >> 8);
        x.b[p_ver + 4]    = (uint8_t)rec;
    }

    *out_len = x.n;
    {
        uint8_t *out = malloc(x.n);
        if (out)
            memcpy(out, x.b, x.n);
        return out;
    }
}

/* --------------------------------------------------------------- HTTP fake */
uint8_t *fakegen_http(const char *host, size_t *out_len)
{
    char req[1024];
    int n;
    if (!host || !host[0])
        host = "example.com";
    n = snprintf(req, sizeof(req),
                 "GET / HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                 "Accept: */*\r\n"
                 "\r\n", host);
    if (n <= 0 || (size_t)n >= sizeof(req))
        return NULL;
    {
        uint8_t *out = malloc((size_t)n);
        if (out)
        {
            memcpy(out, req, (size_t)n);
            *out_len = (size_t)n;
        }
        return out;
    }
}

/* --------------------------------------------------------------- file fake */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

uint8_t *fakegen_load(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    uint8_t *data;
    size_t i, hexn = 0;
    bool maybe_hex = true;

    if (!f)
    {
        log_msg(LOG_ERR, "fake: cannot open %s", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 65000)
    {
        fclose(f);
        log_msg(LOG_ERR, "fake: bad size %ld in %s", sz, path);
        return NULL;
    }
    data = malloc((size_t)sz);
    if (!data) { fclose(f); return NULL; }
    if (fread(data, 1, (size_t)sz, f) != (size_t)sz)
    {
        fclose(f);
        free(data);
        return NULL;
    }
    fclose(f);

    for (i = 0; i < (size_t)sz; i++)
    {
        char c = (char)data[i];
        if (hexval(c) >= 0)
            hexn++;
        else if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            ;
        else
        {
            maybe_hex = false;
            break;
        }
    }
    if (maybe_hex && hexn > 20 && hexn % 2 == 0)
    {
        uint8_t *out = malloc(hexn / 2);
        size_t o = 0;
        if (!out) { free(data); return NULL; }
        for (i = 0; i + 1 < (size_t)sz && o < hexn / 2; )
        {
            int hi = hexval((char)data[i]);
            if (hi < 0) { i++; continue; }
            {
                size_t j = i + 1;
                int lo = -1;
                while (j < (size_t)sz && (lo = hexval((char)data[j])) < 0) j++;
                if (lo < 0) break;
                out[o++] = (uint8_t)((hi << 4) | lo);
                i = j + 1;
            }
        }
        free(data);
        *out_len = o;
        return out;
    }
    *out_len = (size_t)sz;
    return data;
}
