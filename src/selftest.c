/* DBDPI - built-in self tests: parsers, host lists, argument tokenizer,
 * fake ClientHello generation and the desync engine at packet level.
 * Runs without the WinDivert driver and without administrator rights
 * (only the DLL's checksum helpers are used). */
#include "dbdpi.h"

static int fails = 0;

#define CHECK(name, cond)                                        \
    do {                                                         \
        bool ok_ = (cond);                                       \
        printf("%-30s %s\n", name, ok_ ? "OK" : "FAIL");          \
        if (!ok_) fails++;                                       \
    } while (0)

/* ------------------------------------------------------------ test fixtures */

/* Build a minimal but well-formed TLS ClientHello payload for `host`. */
static size_t mk_ch(uint8_t *ch, size_t cap, const char *host)
{
    size_t n = 0, sni_len = strlen(host);
    uint16_t rec, hs, listlen, namelen, extlen;

    if (sni_len == 0 || sni_len > 253 || cap < 128 + sni_len)
        return 0;
    namelen = (uint16_t)sni_len;
    rec = (uint16_t)(4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 9 + sni_len);
    extlen = (uint16_t)(9 + sni_len);
    listlen = (uint16_t)(3 + sni_len);
    hs = (uint16_t)(rec - 4);

    ch[n++] = 0x16; ch[n++] = 0x03; ch[n++] = 0x01;
    ch[n++] = (uint8_t)(rec >> 8); ch[n++] = (uint8_t)rec;
    ch[n++] = 0x01;
    ch[n++] = (uint8_t)(hs >> 16); ch[n++] = (uint8_t)(hs >> 8); ch[n++] = (uint8_t)hs;
    ch[n++] = 0x03; ch[n++] = 0x03;
    memset(ch + n, 0xAB, 32); n += 32;
    ch[n++] = 0;                                        /* session id len */
    ch[n++] = 0; ch[n++] = 2; ch[n++] = 0x13; ch[n++] = 0x01;
    ch[n++] = 1; ch[n++] = 0;                           /* compression */
    ch[n++] = (uint8_t)(extlen >> 8); ch[n++] = (uint8_t)extlen;
    ch[n++] = 0x00; ch[n++] = 0x00;                     /* SNI ext */
    ch[n++] = 0x00; ch[n++] = (uint8_t)(5 + sni_len);
    ch[n++] = (uint8_t)(listlen >> 8); ch[n++] = (uint8_t)listlen;
    ch[n++] = 0x00;
    ch[n++] = (uint8_t)(namelen >> 8); ch[n++] = (uint8_t)namelen;
    memcpy(ch + n, host, sni_len); n += sni_len;
    return n;
}

/* Build a synthetic outbound IPv4/TCP packet carrying `payload`. */
static size_t mk_pkt(uint8_t *buf, size_t cap, const uint8_t *payload,
                     size_t plen, uint32_t seq, uint32_t ack)
{
    WINDIVERT_IPHDR *ip = (WINDIVERT_IPHDR *)buf;
    WINDIVERT_TCPHDR *tcp = (WINDIVERT_TCPHDR *)(buf + sizeof(WINDIVERT_IPHDR));
    size_t total = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR) + plen;

    if (total > cap || sizeof(WINDIVERT_IPHDR) != 20 ||
        sizeof(WINDIVERT_TCPHDR) != 20)
        return 0;
    memset(buf, 0, total);
    ip->Version = 4;
    ip->HdrLength = 5;
    ip->TTL = 128;
    ip->Protocol = 6;
    ip->Length = htons((uint16_t)total);
    ip->SrcAddr = htonl(0x0A000001);
    ip->DstAddr = htonl(0x5DB8D822);
    tcp->SrcPort = htons(50000);
    tcp->DstPort = htons(443);
    tcp->SeqNum = htonl(seq);
    tcp->AckNum = htonl(ack);
    tcp->HdrLength = 5;
    tcp->Ack = 1;
    tcp->Psh = 1;
    tcp->Window = htons(65535);
    if (plen)
        memcpy(buf + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR),
               payload, plen);
    WinDivertHelperCalcChecksums(buf, (UINT)total, NULL, 0);
    return total;
}

/* ------------------------------------------------------- verification tools */

static void sum_add(uint32_t *sum, const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i + 1 < n; i += 2)
        *sum += ((uint32_t)p[i] << 8) | (uint32_t)p[i + 1];
    if (i < n)
        *sum += (uint32_t)p[i] << 8;
}

/* Independent re-computation of the IPv4/TCP checksum of a whole packet. */
static bool tcp_cksum_valid(const uint8_t *pkt, size_t len)
{
    WINDIVERT_IPHDR *ip = NULL;
    WINDIVERT_IPV6HDR *ip6 = NULL;
    WINDIVERT_TCPHDR *tcp = NULL;
    VOID *data = NULL;
    UINT dlen = 0;
    uint32_t sum = 0;
    size_t tcplen;
    uint8_t ph[2];

    if (!WinDivertHelperParsePacket((VOID *)pkt, (UINT)len, &ip, &ip6, NULL,
                                    NULL, NULL, &tcp, NULL, &data, &dlen,
                                    NULL, NULL) || !tcp || !ip)
        return false;                       /* fixtures are IPv4 only */
    tcplen = (size_t)tcp->HdrLength * 4 + dlen;
    sum_add(&sum, (const uint8_t *)&ip->SrcAddr, 4);
    sum_add(&sum, (const uint8_t *)&ip->DstAddr, 4);
    ph[0] = 0; ph[1] = 6;
    sum_add(&sum, ph, 2);
    ph[0] = (uint8_t)(tcplen >> 8); ph[1] = (uint8_t)tcplen;
    sum_add(&sum, ph, 2);
    sum_add(&sum, (const uint8_t *)tcp, tcplen);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return sum == 0xFFFF;
}

/* Walk the extensions of a ClientHello record: 0 when every declared length
 * fits exactly, i.e. the structure can be parsed without ambiguity. */
static int ch_validate(const uint8_t *p, size_t len)
{
    size_t off, ext_end;
    uint32_t hs_len;
    uint16_t ext_all;
    uint8_t sid_len, comp_len;
    uint16_t cs_len;

    if (len < 9 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 0x01)
        return 1;
    if ((size_t)(((uint16_t)p[3] << 8) | p[4]) + 5 != len)
        return 2;                                   /* record length mismatch */
    hs_len = ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 8) | p[8];
    if ((size_t)hs_len + 9 != len)
        return 3;                                   /* handshake length mismatch */
    off = 9 + 2 + 32;
    if (off + 1 > len) return 4;
    sid_len = p[off]; off += 1 + sid_len;
    if (off + 2 > len) return 5;
    cs_len = (uint16_t)((p[off] << 8) | p[off + 1]); off += 2 + cs_len;
    if (off + 1 > len) return 6;
    comp_len = p[off]; off += 1 + comp_len;
    if (off + 2 > len) return 7;
    ext_all = (uint16_t)((p[off] << 8) | p[off + 1]); off += 2;
    ext_end = off + ext_all;
    if (ext_end != len) return 8;                   /* extension block length */
    while (off < ext_end)
    {
        uint16_t xl;
        if (off + 4 > ext_end) return 9;
        xl = (uint16_t)((p[off + 2] << 8) | p[off + 3]);
        if (off + 4 + xl > ext_end)
            return 10;                              /* extension overruns block */
        off += 4 + xl;
    }
    return (off == ext_end) ? 0 : 11;
}

/* ----------------------------------------------------------- desync batches */

typedef struct {
    uint8_t          **out;
    size_t            *lens;
    int                n;
    WINDIVERT_ADDRESS  addr;
    uint8_t            pkt[4096];
} batch_t;

typedef struct {
    WINDIVERT_TCPHDR *tcp;
    const uint8_t    *data;
    size_t            dlen;
    uint8_t           ttl;
} bview_t;

static bool b_view(const batch_t *b, int i, bview_t *bv)
{
    WINDIVERT_IPHDR *ip = NULL;
    WINDIVERT_IPV6HDR *ip6 = NULL;
    VOID *data = NULL;
    UINT dlen = 0;

    memset(bv, 0, sizeof(*bv));
    if (!b->out || i >= b->n)
        return false;
    if (!WinDivertHelperParsePacket((VOID *)b->out[i], (UINT)b->lens[i], &ip,
                                    &ip6, NULL, NULL, NULL, &bv->tcp, NULL,
                                    &data, &dlen, NULL, NULL) || !bv->tcp)
        return false;
    bv->data = (const uint8_t *)data;
    bv->dlen = dlen;
    bv->ttl = ip ? ip->TTL : ip6->HopLimit;
    return true;
}

static bool run_desync(batch_t *b, const profile_t *p, const uint8_t *payload,
                       size_t payload_len, conn_t *cn,
                       const tls_info_t *ti, const http_info_t *hi)
{
    size_t plen;
    memset(b, 0, sizeof(*b));
    plen = mk_pkt(b->pkt, sizeof(b->pkt), payload, payload_len,
                  0x11111111u, 0x22222222u);
    if (plen == 0)
        return false;
    b->n = desync_apply(p, b->pkt, plen, &b->addr, cn, ti, hi, &b->out,
                        &b->lens);
    return b->n > 0;
}

static void batch_free(batch_t *b)
{
    int i;
    for (i = 0; i < b->n && b->out; i++)
        free(b->out[i]);
    free(b->out);
    free(b->lens);
    b->out = NULL;
    b->lens = NULL;
    b->n = 0;
}

static void test_desync(void)
{
    const uint32_t seq = 0x11111111u, ack = 0x22222222u;
    const char *sni = "www.youtube.com";
    uint8_t ch[512], http[512];
    size_t ch_len, http_len;
    tls_info_t ti;
    http_info_t hi;
    conn_t cn;

    memset(&ti, 0, sizeof(ti));
    memset(&hi, 0, sizeof(hi));
    memset(&cn, 0, sizeof(cn));
    cn.autottl_hops = -1;

    ch_len = mk_ch(ch, sizeof(ch), sni);
    if (ch_len == 0 || !tls_parse_client_hello(ch, ch_len, &ti) ||
        !ti.is_client_hello || strcmp(ti.sni, sni) != 0)
        { printf("desync engine: FAIL (tls fixture broken)\n"); fails++; return; }
    http_len = (size_t)snprintf((char *)http, sizeof(http),
                                "GET / HTTP/1.1\r\nHost: %s\r\n"
                                "User-Agent: t\r\n\r\n", sni);
    if (http_len >= sizeof(http) ||
        !http_parse_request(http, http_len, &hi) || !hi.is_request)
        { printf("desync engine: FAIL (http fixture broken)\n"); fails++; return; }

    /* --- split in the middle of the second-level domain --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0, v1;
        int want = ti.sni_off + 7;      /* "www.you|tube.com" inside the SNI */
        bool ok;
        memset(&p, 0, sizeof(p));
        p.mode = DESYNC_SPLIT;
        p.split_pos_n = 1;
        p.split_pos[0].is_marker = true;
        p.split_pos[0].marker = SP_MIDSLD;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 2 &&
             b_view(&b, 0, &v0) && b_view(&b, 1, &v1) &&
             v0.dlen == (size_t)want && v1.dlen == ch_len - (size_t)want &&
             memcmp(v0.data, ch, (size_t)want) == 0 &&
             memcmp(v1.data, ch + want, ch_len - (size_t)want) == 0 &&
             v0.data[want - 1] == 'u' && v1.data[0] == 't' &&
             ntohl(v0.tcp->SeqNum) == seq &&
             ntohl(v1.tcp->SeqNum) == seq + (uint32_t)want &&
             tcp_cksum_valid(b.out[0], b.lens[0]) &&
             tcp_cksum_valid(b.out[1], b.lens[1]) &&
             b.addr.TCPChecksum && b.addr.IPChecksum;
        CHECK("desync split midsld", ok);
        batch_free(&b);
    }

    /* --- multisplit at the SNI extension and the SNI value --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0, v1, v2;
        bool ok;
        int p1 = ti.sni_ext_off, p2 = ti.sni_off;
        memset(&p, 0, sizeof(p));
        p.mode = DESYNC_MULTISPLIT;
        p.split_pos_n = 2;
        p.split_pos[0].is_marker = true;
        p.split_pos[0].marker = SP_SNI;
        p.split_pos[1].is_marker = true;
        p.split_pos[1].marker = SP_SNIEXT;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 3 &&
             b_view(&b, 0, &v0) && b_view(&b, 1, &v1) && b_view(&b, 2, &v2) &&
             p1 > 0 && p2 > p1 && v0.dlen == (size_t)p1 &&
             v1.dlen == (size_t)(p2 - p1) && v2.dlen == ch_len - (size_t)p2 &&
             ntohl(v0.tcp->SeqNum) == seq &&
             ntohl(v1.tcp->SeqNum) == seq + (uint32_t)p1 &&
             ntohl(v2.tcp->SeqNum) == seq + (uint32_t)p2 &&
             memcmp(v1.data, ch + p1, (size_t)(p2 - p1)) == 0 &&
             memcmp(v2.data, ch + p2, ch_len - (size_t)p2) == 0;
        CHECK("desync multisplit sni/sniext", ok);
        batch_free(&b);
    }

    /* --- disorder: tail segment is sent first --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0, v1;
        bool ok;
        memset(&p, 0, sizeof(p));
        int want = ti.sni_off + 7;
        p.mode = DESYNC_DISORDER;
        p.split_pos_n = 1;
        p.split_pos[0].is_marker = true;
        p.split_pos[0].marker = SP_MIDSLD;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 2 &&
             b_view(&b, 0, &v0) && b_view(&b, 1, &v1) &&
             ntohl(v0.tcp->SeqNum) == seq + (uint32_t)want &&
             v0.dlen == ch_len - (size_t)want &&
             ntohl(v1.tcp->SeqNum) == seq && v1.dlen == (size_t)want &&
             memcmp(v0.data, ch + want, ch_len - (size_t)want) == 0 &&
             memcmp(v1.data, ch, (size_t)want) == 0;
        CHECK("desync disorder", ok);
        batch_free(&b);
    }

    /* --- fake: badsum + badseq, fake first, original last --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0, v1;
        tls_info_t fti;
        bool ok;
        memset(&p, 0, sizeof(p));
        p.mode = DESYNC_FAKE;
        p.fake_gen = true;
        p.fooling = FOOL_BADSUM | FOOL_BADSEQ;
        p.badseq_delta = -100000;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 2 &&
             b_view(&b, 0, &v0) && b_view(&b, 1, &v1) &&
             /* fake carries the same SNI but is not the original payload */
             v0.dlen > ch_len && v0.dlen != ch_len &&
             tls_parse_client_hello(v0.data, v0.dlen, &fti) &&
             fti.is_client_hello && strcmp(fti.sni, sni) == 0 &&
             ntohl(v0.tcp->SeqNum) ==
                 (uint32_t)((int64_t)seq + p.badseq_delta) &&
             ntohl(v0.tcp->AckNum) == ack &&
             !tcp_cksum_valid(b.out[0], b.lens[0]) &&      /* badsum stays bad */
             v1.dlen == ch_len && memcmp(v1.data, ch, ch_len) == 0 &&
             ntohl(v1.tcp->SeqNum) == seq &&
             tcp_cksum_valid(b.out[1], b.lens[1]) &&
             b.addr.TCPChecksum && b.addr.IPChecksum;
        CHECK("desync fake badsum/badseq", ok);
        batch_free(&b);
    }

    /* --- ttl fooling with a measured path, and without one --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0;
        bool ok;
        memset(&p, 0, sizeof(p));
        p.mode = DESYNC_FAKE;
        p.fake_gen = true;
        p.fooling = FOOL_TTL;
        p.autottl = true;
        p.autottl_delta = 3;
        p.autottl_min = 3;
        p.autottl_max = 64;
        cn.autottl_hops = 10;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 2 &&
             b_view(&b, 0, &v0) && v0.ttl == 7;             /* 10 - 3 */
        CHECK("desync fake ttl autottl", ok);
        batch_free(&b);

        cn.autottl_hops = -1;                               /* path unknown */
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 1 &&
             b_view(&b, 0, &v0) && v0.dlen == ch_len &&
             memcmp(v0.data, ch, ch_len) == 0;              /* fakes skipped */
        CHECK("desync fake ttl unknown", ok);
        batch_free(&b);
    }

    /* --- datanoack: the fake is an ACK-less data packet --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0;
        bool ok;
        memset(&p, 0, sizeof(p));
        p.mode = DESYNC_FAKE;
        p.fake_gen = true;
        p.fooling = FOOL_DATANOACK;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 2 &&
             b_view(&b, 0, &v0) && v0.tcp->Ack == 0 &&
             tcp_cksum_valid(b.out[0], b.lens[0]);
        CHECK("desync fake datanoack", ok);
        batch_free(&b);
    }

    /* --- methodeol: first segment carries CRLF at seq-2 --- */
    {
        profile_t p;
        batch_t b;
        bview_t v0, v1;
        bool ok;
        memset(&p, 0, sizeof(p));
        int want = ti.sni_off + 7;
        p.mode = DESYNC_MULTISPLIT;
        p.methodeol = true;
        p.split_pos_n = 1;
        p.split_pos[0].is_marker = true;
        p.split_pos[0].marker = SP_MIDSLD;
        ok = run_desync(&b, &p, ch, ch_len, &cn, &ti, NULL) && b.n == 2 &&
             b_view(&b, 0, &v0) && b_view(&b, 1, &v1) &&
             ntohl(v0.tcp->SeqNum) == seq - 2 &&
             v0.dlen == (size_t)want + 2 && v0.data[0] == '\r' &&
             v0.data[1] == '\n' && memcmp(v0.data + 2, ch, (size_t)want) == 0 &&
             ntohl(v1.tcp->SeqNum) == seq + (uint32_t)want &&
             memcmp(v1.data, ch + want, ch_len - (size_t)want) == 0 &&
             tcp_cksum_valid(b.out[0], b.lens[0]);
        CHECK("desync methodeol", ok);
        batch_free(&b);
    }

    /* --- hostcase in fake mode: same length, checksum recomputed --- */
    {
        profile_t p;
        batch_t b;
        bview_t v1;
        bool ok, pat = false;
        static const char *pats[4] = { "hosT", "hOsT", "HOst", "hoST" };
        int i;
        memset(&p, 0, sizeof(p));
        p.mode = DESYNC_FAKE;
        p.fake_gen = true;
        p.hostcase = true;
        p.fooling = FOOL_BADSUM | FOOL_BADSEQ;
        ok = run_desync(&b, &p, http, http_len, &cn, NULL, &hi) && b.n == 2 &&
             b_view(&b, 1, &v1) && v1.dlen == http_len;
        if (ok)
        {
            for (i = 0; i < 4; i++)
                if (memcmp(v1.data + 16, pats[i], 4) == 0)
                    pat = true;
            if (!pat)
                printf("    hostcase: name=%.4s want=%.4s\n",
                       (const char *)v1.data + 16, (const char *)http + 16);
            else if (v1.data[20] != ':')
                printf("    hostcase: no colon at offset 20\n");
            else if (!tcp_cksum_valid(b.out[1], b.lens[1]))
                printf("    hostcase: original checksum stale\n");
            else if (tcp_cksum_valid(b.out[0], b.lens[0]))
                printf("    hostcase: fake checksum valid (badsum lost)\n");
            ok = pat && v1.data[20] == ':' &&
                 tcp_cksum_valid(b.out[1], b.lens[1]) &&
                 tcp_cksum_valid(b.out[0], b.lens[0]) == false;
        }
        else
            printf("    hostcase: n=%d\n", b.n);
        CHECK("desync hostcase + checksums", ok);
        batch_free(&b);
    }
}

/* ------------------------------------------------------------------ selftest */

int selftest(void)
{
    /* config_parse() below may log; keep it initialized and quiet */
    log_init(NULL, LOG_ERR);

    printf("%s (dbdpi) v%s self test\n", DBDPI_NAME, DBDPI_VERSION);

    /* HTTP */
    {
        const char *req = "GET / HTTP/1.1\r\nHost: www.youtube.com\r\n"
                          "User-Agent: t\r\n\r\n";
        http_info_t hi;
        if (http_parse_request((const uint8_t *)req, strlen(req), &hi) &&
            hi.is_request && !strcmp(hi.host, "www.youtube.com") &&
            hi.method_end_off == 3 && hi.host_off == 22)
            printf("http parse: OK\n");
        else
            { printf("http parse: FAIL (%s off=%d)\n", hi.host, hi.host_off); fails++; }
    }

    /* TLS */
    {
        uint8_t ch[512];
        size_t n = mk_ch(ch, sizeof(ch), "example.com");
        tls_info_t ti;
        if (n && tls_parse_client_hello(ch, n, &ti) && ti.is_client_hello &&
            !strcmp(ti.sni, "example.com") && ti.sni_off == (int)(n - 11) &&
            ti.sni_ext_off == 52)
            printf("tls parse: OK (sni_off=%d)\n", ti.sni_off);
        else
            { printf("tls parse: FAIL (sni=%s off=%d)\n", ti.sni, ti.sni_off); fails++; }
    }

    /* fakegen round-trip and structural consistency */
    {
        size_t fl = 0;
        uint8_t *f = fakegen_tls("test.example.org", &fl);
        tls_info_t ti;
        int rc = f ? ch_validate(f, fl) : -1;
        if (f && tls_parse_client_hello(f, fl, &ti) && ti.is_client_hello &&
            !strcmp(ti.sni, "test.example.org"))
            printf("fakegen tls: OK (%zu bytes)\n", fl);
        else
            { printf("fakegen tls: FAIL\n"); fails++; }
        if (rc == 0)
            printf("fakegen tls structure: OK\n");
        else
            { printf("fakegen tls structure: FAIL (walk error %d)\n", rc); fails++; }
        free(f);
    }

    /* hostlist matching (domains stored reversed and sorted internally) */
    {
        hostlist_t hl;
        memset(&hl, 0, sizeof(hl));
        {
            /* reversed domains, as hostlist_load would store them */
            char *items[] = { "com.example", "com.youtube" };
            size_t i;
            hl.n = 2;
            hl.items = malloc(sizeof(char *) * 2);
            for (i = 0; i < 2; i++)
                hl.items[i] = strdup(items[i]);
            /* already sorted lexicographically */
        }
        if (hostlist_match(&hl, "www.example.com") &&
            hostlist_match(&hl, "EXAMPLE.com") &&
            hostlist_match(&hl, "youtube.com") &&
            !hostlist_match(&hl, "notexample.com") &&
            !hostlist_match(&hl, "example.org"))
            printf("hostlist match: OK\n");
        else
            { printf("hostlist match: FAIL\n"); fails++; }
        hostlist_free(&hl);
    }

    /* service arg file tokenizer: argv[0] + quotes + parsed strategy */
    {
        char line[] = "--dpi-desync=multisplit --split-pos=midsld "
                      "--log=\"C:\\Program Files\\dbdpi\\log.txt\"";
        int argc = 0, rc;
        char **args = tokenize_args(line, &argc);
        config_defaults();
        rc = config_parse(argc, args);
        if (rc == 0 && argc == 4 &&
            !strcmp(args[0], "dbdpi") &&
            !strcmp(args[1], "--dpi-desync=multisplit") &&
            !strcmp(args[2], "--split-pos=midsld") &&
            !strcmp(args[3], "--log=C:\\Program Files\\dbdpi\\log.txt") &&
            g_cfg.prof.mode == DESYNC_MULTISPLIT && g_cfg.prof.split_pos_n == 1)
            printf("tokenize args: OK\n");
        else
            { printf("tokenize args: FAIL (argc=%d rc=%d mode=%d)\n",
                     argc, rc, (int)g_cfg.prof.mode); fails++; }
    }

    test_desync();

    printf(fails ? "SELFTEST: %d FAILURES\n" : "SELFTEST: all passed\n", fails);
    return fails ? 1 : 0;
}
