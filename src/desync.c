/* DBDPI - desync engine: segmentation, fake packets, fooling.
 *
 * All packets we build are TCP-level segments derived from the captured
 * packet (never IP-fragments), so middleboxes see normal TCP traffic.
 */
#include "dbdpi.h"

#include <ctype.h>

#define MAX_OUT_PKTS 256

typedef struct {
    uint8_t *buf;
    size_t   len;
} pkt_t;

typedef struct {
    const uint8_t *pkt;
    size_t         len;
    size_t         tcp_off;         /* start of the TCP header in pkt */
    size_t         payload_off;     /* start of TCP payload in pkt */
    size_t         payload_len;
    bool           is_ipv6;
    WINDIVERT_TCPHDR *tcp;
} pktview_t;

static void pkt_free_all(pkt_t *pkts, int n)
{
    int i;
    for (i = 0; i < n; i++)
        free(pkts[i].buf);
}

/* ---------------------------------------------------------------- helpers */

static bool view_packet(const uint8_t *pkt, size_t len, pktview_t *v)
{
    WINDIVERT_IPHDR  *iph = NULL;
    WINDIVERT_IPV6HDR *ip6h = NULL;
    VOID   *pdata = NULL;
    UINT    plen = 0;

    memset(v, 0, sizeof(*v));
    if (!WinDivertHelperParsePacket((VOID *)pkt, (UINT)len,
                                    &iph, &ip6h, NULL, NULL, NULL,
                                    &v->tcp, NULL,
                                    &pdata, &plen, NULL, NULL))
        return false;
    if (!v->tcp || !pdata)
        return false;
    v->is_ipv6 = (ip6h != NULL);
    v->pkt = pkt;
    v->len = len;
    v->tcp_off = (size_t)((uint8_t *)v->tcp - pkt);
    v->payload_off = (size_t)((uint8_t *)pdata - pkt);
    v->payload_len = plen;
    return true;
}

static uint8_t *pkt_dup(const uint8_t *pkt, size_t len)
{
    uint8_t *b = malloc(len);
    if (b)
        memcpy(b, pkt, len);
    return b;
}

/* Fill in checksums and mark them valid in the address: packets are injected
 * with this same address, and without the flags the stack/NIC would recompute
 * the checksums, undoing deliberate badsum fakes. */
static void pkt_finish(uint8_t *buf, size_t len, WINDIVERT_ADDRESS *addr)
{
    WinDivertHelperCalcChecksums(buf, (UINT)len, addr, 0);
}

/* unmodified copy of the original packet, ready for injection */
static uint8_t *mk_orig(const pktview_t *v, WINDIVERT_ADDRESS *addr)
{
    uint8_t *b = pkt_dup(v->pkt, v->len);
    if (b)
        pkt_finish(b, v->len, addr);
    return b;
}

/* build a segment packet: original headers + given payload */
static uint8_t *mk_segment(const pktview_t *v, uint32_t seq,
                           const uint8_t *data, size_t dlen)
{
    uint8_t *b = malloc(v->payload_off + dlen);
    if (!b)
        return NULL;
    memcpy(b, v->pkt, v->payload_off);
    if (dlen)
        memcpy(b + v->payload_off, data, dlen);
    ((WINDIVERT_TCPHDR *)(b + v->tcp_off))->SeqNum = htonl(seq);
    if (v->is_ipv6)
        ((WINDIVERT_IPV6HDR *)b)->Length = htons((uint16_t)(v->payload_off - 40 + dlen));
    else
        ((WINDIVERT_IPHDR *)b)->Length = htons((uint16_t)(v->payload_off + dlen));
    return b;
}

/* build a fake packet: original headers, given payload, fooling applied */
static uint8_t *mk_fake(const pktview_t *v, uint32_t seq, uint32_t ack,
                        const uint8_t *data, size_t dlen,
                        const profile_t *prof, int ttl_hops,
                        WINDIVERT_ADDRESS *addr)
{
    uint8_t *b = mk_segment(v, seq, data, dlen);
    WINDIVERT_TCPHDR *tcp;
    if (!b)
        return NULL;
    tcp = (WINDIVERT_TCPHDR *)(b + v->tcp_off);
    tcp->AckNum = htonl(ack);

    if (prof->fooling & FOOL_TTL)
    {
        int t = -1;
        if (prof->autottl && ttl_hops >= 0)
        {
            t = ttl_hops - prof->autottl_delta;
            if (t < prof->autottl_min) t = prof->autottl_min;
            if (t > prof->autottl_max) t = prof->autottl_max;
        }
        else if (prof->ttl > 0)
            t = prof->ttl;
        if (t > 0)
        {
            if (v->is_ipv6)
                ((WINDIVERT_IPV6HDR *)b)->HopLimit = (UINT8)t;
            else
                ((WINDIVERT_IPHDR *)b)->TTL = (UINT8)t;
        }
    }
    if (prof->fooling & FOOL_BADSEQ)
        tcp->SeqNum = htonl((uint32_t)((int64_t)seq + prof->badseq_delta));
    if (prof->fooling & FOOL_DATANOACK)
        tcp->Ack = 0;               /* ACK-less data packet: server drops it */
    pkt_finish(b, v->payload_off + dlen, addr);
    if (prof->fooling & FOOL_BADSUM)
        tcp->Checksum ^= 0xFFFF;
    return b;
}

/* ------------------------------------------------------- marker resolution */

/* middle of the second-level domain inside host value */
static int midsld_off(const char *host, int hlen)
{
    int dot_last = -1, dot_prev = -1, i;
    int sld_start, sld_len;
    for (i = hlen - 1; i >= 0; i--)
        if (host[i] == '.')
        {
            if (dot_last < 0) dot_last = i;
            else { dot_prev = i; break; }
        }
    if (dot_last < 0)
    {
        sld_start = 0;
        sld_len = hlen;
    }
    else
    {
        sld_start = (dot_prev >= 0) ? dot_prev + 1 : 0;
        sld_len = dot_last - sld_start;
    }
    if (sld_len <= 0)
        return (hlen > 1) ? hlen / 2 : -1;
    return sld_start + sld_len / 2;
}

static int resolve_marker(split_marker_t m, const pktview_t *v,
                          const tls_info_t *ti, const http_info_t *hi)
{
    const char *host;
    int hoff, hlen, mid;

    switch (m)
    {
    case SP_METHOD:
        return hi ? hi->method_end_off : -1;
    case SP_HOST:
        if (hi && hi->is_request) return hi->host_off;
        if (ti && ti->is_client_hello) return ti->sni_off;
        return -1;
    case SP_ENDHOST:
        if (hi && hi->is_request) return hi->host_off + hi->host_len;
        if (ti && ti->is_client_hello) return ti->sni_off + (int)strlen(ti->sni);
        return -1;
    case SP_MIDSLD:
        host = NULL;
        hoff = hlen = 0;
        if (hi && hi->is_request && hi->host_len)
            { host = hi->host; hoff = hi->host_off; hlen = hi->host_len; }
        else if (ti && ti->is_client_hello && ti->sni[0])
            { host = ti->sni; hoff = ti->sni_off; hlen = (int)strlen(ti->sni); }
        if (!host)
            return -1;
        mid = midsld_off(host, hlen);
        return (mid >= 0) ? hoff + mid : -1;
    case SP_SNI:
        if (ti && ti->is_client_hello) return ti->sni_off;
        if (hi && hi->is_request) return hi->host_off;
        return -1;
    case SP_SNIEXT:
        return (ti && ti->is_client_hello) ? ti->sni_ext_off : -1;
    default:
        return -1;
    }
}

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* ---------------------------------------------------------------- HTTP mods */

/* same-length HTTP header tricks, applied to a packet copy */
static uint8_t *apply_http_mods(const pktview_t *v, const profile_t *prof,
                                const http_info_t *hi, size_t *out_len)
{
    uint8_t *b = pkt_dup(v->pkt, v->len);
    int i, value_off;
    if (!b)
        return NULL;
    *out_len = v->len;
    if (!(hi && hi->is_request && hi->host_off > 0))
        return b;
    /* hi->host_off is payload-relative, i walks the whole packet */
    value_off = (int)v->payload_off + hi->host_off;
    for (i = (int)v->payload_off; i + 5 <= value_off; i++)
    {
        if (tolower(b[i]) == 'h' && tolower(b[i+1]) == 'o' &&
            tolower(b[i+2]) == 's' && tolower(b[i+3]) == 't' &&
            b[i+4] == ':' && i >= 1 && b[i-1] == '\n')
        {
            static const char *pat[4] = { "hosT", "hOsT", "HOst", "hoST" };
            const char *p;
            int c;
            if (prof->hostcase)
            {
                p = pat[GetTickCount() & 3];
                for (c = 0; c < 4; c++)
                    b[i + c] = (uint8_t)p[c];
            }
            if (prof->hosttab && b[i + 5] == ' ')
                b[i + 5] = '\t';
            break;
        }
    }
    return b;
}

/* ---------------------------------------------------------------- desync */

static bool add_pkt(pkt_t *arr, int *n, uint8_t *buf, size_t len)
{
    if (!buf)
        return false;
    if (*n >= MAX_OUT_PKTS)
    {
        free(buf);
        return false;
    }
    arr[*n].buf = buf;
    arr[*n].len = len;
    (*n)++;
    return true;
}

int desync_apply(const profile_t *prof, const uint8_t *pkt, size_t len,
                 WINDIVERT_ADDRESS *addr, conn_t *cn,
                 const tls_info_t *ti, const http_info_t *hi,
                 uint8_t ***out, size_t **out_lens)
{
    pktview_t v;
    pkt_t pkts[MAX_OUT_PKTS];
    int n = 0, i;
    int positions[MAX_SPLIT_POS + 1];
    int npos = 0;
    uint32_t seq, ack;
    const uint8_t *payload;
    uint8_t *work = NULL;
    uint8_t *fake_tls = NULL, *fake_http = NULL;
    size_t fake_tls_len = 0, fake_http_len = 0;
    int ttl_hops = cn ? cn->autottl_hops : -1;
    bool fakes_ok;
    int ret = -1;

    *out = NULL;
    *out_lens = NULL;
    memset(pkts, 0, sizeof(pkts));

    if (!view_packet(pkt, len, &v) || v.payload_len == 0)
        return -1;
    payload = pkt + v.payload_off;
    seq = ntohl(v.tcp->SeqNum);
    ack = ntohl(v.tcp->AckNum);

    /* Fakes are only safe when they are guaranteed not to reach the server.
     * With TTL fooling and no TTL source the fake would keep the original TTL
     * and corrupt the stream, so drop the fakes instead. */
    fakes_ok = !(prof->fooling & FOOL_TTL) || prof->ttl > 0 ||
               (prof->autottl && ttl_hops >= 0);
    if (!fakes_ok)
        log_msg(LOG_DEBUG, "conn: fooling=ttl without a known path length, "
                           "fakes skipped");

    /* ---- resolve split positions ---- */
    if (prof->mode == DESYNC_SPLIT || prof->mode == DESYNC_MULTISPLIT ||
        prof->mode == DESYNC_DISORDER || prof->mode == DESYNC_FAKEDSPLIT)
    {
        for (i = 0; i < prof->split_pos_n && npos < MAX_SPLIT_POS; i++)
        {
            int p = prof->split_pos[i].is_marker
                        ? resolve_marker(prof->split_pos[i].marker, &v, ti, hi)
                        : prof->split_pos[i].value;
            if (p <= 0 || (size_t)p >= v.payload_len)
                continue;
            positions[npos++] = p;
        }
        if (npos == 0 && !prof->methodeol)
        {
            log_msg(LOG_DEBUG, "conn: no valid split positions, passthrough");
            return -1;
        }
        qsort(positions, (size_t)npos, sizeof(int), cmp_int);
        for (i = 1; i < npos; )
        {
            if (positions[i] == positions[i - 1])
            {
                memmove(positions + i, positions + i + 1,
                        (size_t)(npos - i - 1) * sizeof(int));
                npos--;
            }
            else
                i++;
        }
    }

    /* ---- fake payloads (only where they can be useful) ---- */
    if ((prof->mode == DESYNC_FAKE || prof->mode == DESYNC_FAKEDSPLIT) &&
        fakes_ok)
    {
        if (prof->fake_tls_path)
            /* an explicitly requested file is used as-is: never silently
             * substitute the built-in generator for it */
            fake_tls = fakegen_load(prof->fake_tls_path, &fake_tls_len);
        else if (ti && ti->is_client_hello)
            fake_tls = fakegen_tls(ti->sni[0] ? ti->sni : "www.google.com",
                                   &fake_tls_len);
        if (prof->fake_http_path)
            fake_http = fakegen_load(prof->fake_http_path, &fake_http_len);
        else if (hi && hi->is_request)
            fake_http = fakegen_http(hi->host[0] ? hi->host : "example.com",
                                     &fake_http_len);
        if (!fake_tls && !fake_http)
        {
            log_msg(LOG_DEBUG, "conn: no fake payload available, passthrough");
            return -1;
        }
    }

    /* ---- base packet (with HTTP mods) ---- */
    if (prof->hostcase || prof->hosttab)
    {
        size_t wlen;
        work = apply_http_mods(&v, prof, hi, &wlen);
        if (!work)
            goto done;
        if (!view_packet(work, wlen, &v))
            goto done;
        payload = work + v.payload_off;
        pkt = work;
        len = wlen;
    }

    /* ---- build output packets ---- */
    if (prof->mode == DESYNC_FAKE)
    {
        const uint8_t *fp = NULL;
        size_t fl = 0;
        int rep = prof->fake_repeats < 1 ? 1 : prof->fake_repeats;

        if (ti && ti->is_client_hello && fake_tls)
            { fp = fake_tls;  fl = fake_tls_len; }
        else if (hi && hi->is_request && fake_http)
            { fp = fake_http; fl = fake_http_len; }
        if (fp)
        {
            if (rep > 16) rep = 16;
            for (i = 0; i < rep; i++)
            {
                uint8_t *f = mk_fake(&v, seq, ack, fp, fl, prof, ttl_hops, addr);
                if (!add_pkt(pkts, &n, f, v.payload_off + fl))
                    goto done;
            }
        }
        if (!add_pkt(pkts, &n, mk_orig(&v, addr), v.len))
            goto done;
    }
    else if (prof->mode == DESYNC_SPLIT || prof->mode == DESYNC_MULTISPLIT ||
             prof->mode == DESYNC_DISORDER || prof->mode == DESYNC_FAKEDSPLIT)
    {
        int seg_start[MAX_SPLIT_POS + 2], seg_end[MAX_SPLIT_POS + 2];
        int nseg = 0, s;
        int pad = prof->methodeol ? 2 : 0;

        seg_start[0] = 0;
        for (i = 0; i < npos; i++)
        {
            seg_end[nseg] = positions[i];
            seg_start[nseg + 1] = positions[i];
            nseg++;
        }
        seg_end[nseg] = (int)v.payload_len;
        nseg++;

        for (s = 0; s < nseg; s++)
        {
            uint32_t sseq = (uint32_t)((int64_t)seq + seg_start[s] -
                                       (s == 0 ? pad : 0));
            if (s == 0 && pad)
            {
                size_t body = (size_t)(seg_end[0] - seg_start[0]);
                size_t seg_len = v.payload_off + pad + body;
                uint8_t *seg = malloc(seg_len);
                if (!seg)
                    goto done;
                memcpy(seg, pkt, v.payload_off);
                seg[v.payload_off] = '\r';
                seg[v.payload_off + 1] = '\n';
                if (body)
                    memcpy(seg + v.payload_off + pad, payload, body);
                ((WINDIVERT_TCPHDR *)(seg + v.tcp_off))->SeqNum = htonl(sseq);
                if (v.is_ipv6)
                    ((WINDIVERT_IPV6HDR *)seg)->Length =
                        htons((uint16_t)(v.payload_off - 40 + pad + body));
                else
                    ((WINDIVERT_IPHDR *)seg)->Length =
                        htons((uint16_t)(v.payload_off + pad + body));
                pkt_finish(seg, seg_len, addr);
                if (!add_pkt(pkts, &n, seg, seg_len))
                    goto done;
                continue;
            }
            {
                size_t plen = (size_t)(seg_end[s] - seg_start[s]);
                uint8_t *seg = mk_segment(&v, sseq, payload + seg_start[s], plen);
                if (!seg)
                    goto done;
                pkt_finish(seg, v.payload_off + plen, addr);
                if (!add_pkt(pkts, &n, seg, v.payload_off + plen))
                    goto done;
            }
        }

        if (prof->mode == DESYNC_FAKEDSPLIT && fakes_ok)
        {
            /* Prepend fake copies before every segment; the fake of the
             * segment carrying the start of the request uses the generated
             * payload. Fakes are collected first (so a failure here leaks
             * nothing), then interleaved with their segments. */
            pkt_t fakes[MAX_OUT_PKTS];
            int fake_src[MAX_OUT_PKTS];
            int nfake = 0, src, f;
            int rep = prof->fake_repeats < 1 ? 1 : prof->fake_repeats;
            int attach = pad ? 1 : 0;   /* index of segment holding the hello */
            bool fok = true;

            if (rep > 16) rep = 16;
            for (src = 0; src < n && fok; src++)
            {
                int k;
                const uint8_t *use;
                size_t use_len;
                uint32_t fseq, fack;

                if (src == attach && ti && ti->is_client_hello && fake_tls)
                    { use = fake_tls; use_len = fake_tls_len; }
                else if (src == attach && hi && hi->is_request && fake_http)
                    { use = fake_http; use_len = fake_http_len; }
                else
                    { use = pkts[src].buf + v.payload_off;
                      use_len = pkts[src].len - v.payload_off; }
                fseq = ntohl(((WINDIVERT_TCPHDR *)(pkts[src].buf + v.tcp_off))->SeqNum);
                fack = ntohl(((WINDIVERT_TCPHDR *)(pkts[src].buf + v.tcp_off))->AckNum);

                for (k = 0; k < rep; k++)
                {
                    uint8_t *fk;
                    if (nfake >= MAX_OUT_PKTS)
                    {
                        fok = false;
                        break;
                    }
                    fk = mk_fake(&v, fseq, fack, use, use_len, prof,
                                 ttl_hops, addr);
                    if (!fk)
                    {
                        fok = false;
                        break;
                    }
                    fakes[nfake].buf = fk;
                    fakes[nfake].len = v.payload_off + use_len;
                    fake_src[nfake] = src;
                    nfake++;
                }
            }
            if (!fok)
            {
                for (f = 0; f < nfake; f++)
                    free(fakes[f].buf);
                goto done;      /* segments are freed by the common error path */
            }
            if ((size_t)n + (size_t)nfake > MAX_OUT_PKTS)
            {
                for (f = 0; f < nfake; f++)
                    free(fakes[f].buf);
                log_msg(LOG_DEBUG, "conn: fakedsplit overflow, fakes skipped");
            }
            else
            {
                pkt_t withf[MAX_OUT_PKTS];
                int nf = 0;
                for (src = 0; src < n; src++)
                {
                    for (f = 0; f < nfake; f++)
                        if (fake_src[f] == src)
                            withf[nf++] = fakes[f];
                    withf[nf++] = pkts[src];
                }
                memcpy(pkts, withf, sizeof(pkt_t) * (size_t)nf);
                n = nf;
            }
        }

        if (prof->mode == DESYNC_DISORDER)
        {
            for (i = 0; i < n / 2; i++)
            {
                pkt_t t = pkts[i];
                pkts[i] = pkts[n - 1 - i];
                pkts[n - 1 - i] = t;
            }
        }
    }
    else
    {
        if (!add_pkt(pkts, &n, mk_orig(&v, addr), v.len))
            goto done;
    }

    /* ---- output ---- */
    {
        uint8_t **bufs = malloc(sizeof(uint8_t *) * (size_t)n);
        size_t *lens = malloc(sizeof(size_t) * (size_t)n);
        if (!bufs || !lens)
        {
            free(bufs);
            free(lens);
            goto done;
        }
        for (i = 0; i < n; i++)
        {
            bufs[i] = pkts[i].buf;
            lens[i] = pkts[i].len;
        }
        *out = bufs;
        *out_lens = lens;
        ret = n;
    }

done:
    if (ret < 0)
        pkt_free_all(pkts, n);
    free(work);
    free(fake_tls);
    free(fake_http);
    return ret;
}
