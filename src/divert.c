/* DBDPI - WinDivert packet loop */
#include "dbdpi.h"

static HANDLE g_handle = INVALID_HANDLE_VALUE;
static volatile LONG g_running = 0;
static volatile LONG g_stop = 0;

static uint64_t now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

/* build the WinDivert filter for the configured ports */
static bool build_filter(char *out, size_t bl, const uint16_t *ports, int n)
{
    char dpart[512], spart[512];
    size_t dl = 0, sl = 0;
    int i, need;

    dpart[0] = spart[0] = 0;
    for (i = 0; i < n; i++)
    {
        int r1 = snprintf(dpart + dl, sizeof(dpart) - dl,
                          "%stcp.DstPort == %u", i ? " or " : "", ports[i]);
        int r2 = snprintf(spart + sl, sizeof(spart) - sl,
                          "%stcp.SrcPort == %u", i ? " or " : "", ports[i]);
        if (r1 < 0 || r2 < 0 || (size_t)r1 >= sizeof(dpart) - dl ||
            (size_t)r2 >= sizeof(spart) - sl)
        {
            log_msg(LOG_ERR, "too many ports for the WinDivert filter");
            return false;
        }
        dl += (size_t)r1;
        sl += (size_t)r2;
    }
    need = snprintf(out, bl,
                    "tcp and (outbound and (%s) or "
                    "inbound and (%s) and tcp.Syn == 1 and tcp.Ack == 1)",
                    dpart, spart);
    if (need < 0 || (size_t)need >= bl)
    {
        log_msg(LOG_ERR, "WinDivert filter too long (%d bytes, max %zu)",
                need, bl);
        return false;
    }
    return true;
}

static void handle_inbound_synack(const uint8_t *pkt, size_t len,
                                  const WINDIVERT_ADDRESS *addr,
                                  WINDIVERT_TCPHDR *tcp,
                                  const uint8_t *src, const uint8_t *dst,
                                  uint16_t sport, uint16_t dport, bool ipv6)
{
    conn_t *cn;
    const WINDIVERT_IPHDR *iph = (const WINDIVERT_IPHDR *)pkt;
    const WINDIVERT_IPV6HDR *ip6 = (const WINDIVERT_IPV6HDR *)pkt;
    int ttl, base, hops;

    (void)len; (void)addr; (void)tcp;
    /* The flow is tracked from its SYN, but create the entry here too: this
     * makes autottl measurement work even if the SYN was missed. */
    cn = conntrack_get_or_add(dst, dport, src, sport, ipv6 ? 6 : 4);
    if (!cn)
        return;
    ttl = ipv6 ? ip6->HopLimit : iph->TTL;
    if (ttl > 128)      base = 255;
    else if (ttl > 64)  base = 128;
    else                base = 64;
    hops = base - ttl;
    if (hops < 0) hops = 0;
    cn->autottl_hops = hops;
    log_msg(LOG_DEBUG, "autottl: path len to server = %d", hops);
}

static void handle_outbound_data(HANDLE h, uint8_t *pkt, size_t len,
                                 WINDIVERT_ADDRESS *addr,
                                 WINDIVERT_TCPHDR *tcp,
                                 const uint8_t *payload, UINT payload_len,
                                 const uint8_t *src, uint16_t sport,
                                 const uint8_t *dst, uint16_t dport, bool ipv6)
{
    conn_t *cn;
    uint32_t seq = ntohl(tcp->SeqNum);
    tls_info_t ti;
    http_info_t hi;
    bool is_tls = false, is_http = false;
    const char *host = NULL;
    uint8_t **bufs = NULL;
    size_t *lens = NULL;
    int n, i;

    InterlockedIncrement64(&g_stats.pkt_total);

    cn = conntrack_get_or_add(src, sport, dst, dport, ipv6 ? 6 : 4);
    if (!cn)
    {
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        return;
    }
    if (cn->passthrough)
    {
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        return;
    }
    if (cn->desync_done && seq != cn->first_seq)
    {
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        return;
    }

    memset(&ti, 0, sizeof(ti));
    memset(&hi, 0, sizeof(hi));
    is_tls = payload_len >= 6 && payload[0] == 0x16 && payload[1] == 0x03 &&
             tls_parse_client_hello(payload, payload_len, &ti);
    if (!is_tls)
        is_http = http_parse_request(payload, payload_len, &hi);

    if (is_tls && ti.is_client_hello && ti.sni[0])
        host = ti.sni;
    else if (is_http && hi.is_request && hi.host[0])
        host = hi.host;

    log_msg(LOG_DEBUG,
            "%s %u->%u %s: %s%s",
            ipv6 ? "tcp6" : "tcp4", sport, dport,
            is_tls ? "tls" : (is_http ? "http" : "???"),
            host ? "host=" : "no host",
            host ? host : "");

    /* hostlist gate */
    if (g_cfg.hostlist.n || g_cfg.hostlist_exclude.n)
    {
        bool ok = host && (!g_cfg.hostlist.n || hostlist_match(&g_cfg.hostlist, host));
        if (ok && host && hostlist_match(&g_cfg.hostlist_exclude, host))
            ok = false;
        if (!ok)
        {
            log_msg(LOG_DEBUG, "host not in list, passthrough");
            InterlockedIncrement64(&g_stats.pkt_hostlist_miss);
            cn->desync_done = true;
            cn->first_seq = seq;
            WinDivertSend(h, pkt, (UINT)len, NULL, addr);
            return;
        }
    }

    if (g_cfg.prof.max_payload && payload_len > g_cfg.prof.max_payload)
    {
        log_msg(LOG_DEBUG, "payload %u > max, passthrough", payload_len);
        InterlockedIncrement64(&g_stats.pkt_passthrough);
        cn->desync_done = true;
        cn->first_seq = seq;
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        return;
    }

    if (g_cfg.prof.mode == DESYNC_NONE)
    {
        cn->desync_done = true;
        cn->first_seq = seq;
        InterlockedIncrement64(&g_stats.pkt_passthrough);
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        return;
    }

    /* dry-run: log what would happen but send original */
    if (g_cfg.dry_run)
    {
        log_msg(LOG_INFO, "dry-run: would desync %s %u->%u %s=%s mode=%d",
                ipv6 ? "tcp6" : "tcp4", sport, dport,
                is_tls ? "sni" : "host",
                host ? host : "?", (int)g_cfg.prof.mode);
        InterlockedIncrement64(&g_stats.pkt_desync);
        cn->desync_done = true;
        cn->first_seq = seq;
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        return;
    }

    n = desync_apply(&g_cfg.prof, pkt, len, addr, cn,
                     is_tls ? &ti : NULL, is_http ? &hi : NULL,
                     &bufs, &lens);
    if (n <= 0)
    {
        log_msg(LOG_DEBUG, "desync: cannot apply, sending original");
        InterlockedIncrement64(&g_stats.pkt_passthrough);
        WinDivertSend(h, pkt, (UINT)len, NULL, addr);
        cn->desync_done = true;
        cn->first_seq = seq;
        return;
    }
    log_msg(LOG_DEBUG, "desync: injecting %d packets (mode %d)", n, g_cfg.prof.mode);
    InterlockedIncrement64(&g_stats.pkt_desync);
    for (i = 0; i < n; i++)
    {
        if (!WinDivertSend(h, bufs[i], (UINT)lens[i], NULL, addr))
            log_msg(LOG_ERR, "WinDivertSend failed (error %lu)", GetLastError());
        free(bufs[i]);
    }
    free(bufs);
    free(lens);

    cn->desync_done = true;
    cn->first_seq = seq;
}

void divert_shutdown(void)
{
    /* The flag also covers the window where the loop has not opened the
     * handle yet (e.g. a service stop right after start). */
    InterlockedExchange(&g_stop, 1);
    if (g_handle != INVALID_HANDLE_VALUE)
        WinDivertShutdown(g_handle, WINDIVERT_SHUTDOWN_RECV);
}

static void log_stats(void)
{
    log_msg(LOG_INFO, "stats: total=%lld desync=%lld pass=%lld hostmiss=%lld",
            (long long)g_stats.pkt_total,
            (long long)g_stats.pkt_desync,
            (long long)g_stats.pkt_passthrough,
            (long long)g_stats.pkt_hostlist_miss);
}

int divert_run(void)
{
    char filter[1024];
    uint8_t pkt[MAX_PACKET];
    WINDIVERT_ADDRESS addr;
    UINT rlen;
    uint64_t last_sweep = 0;
    uint64_t last_stats = 0;
    uint64_t last_hostlist_check = 0;
    uint64_t start_ms;

    if (!build_filter(filter, sizeof(filter), g_cfg.ports, g_cfg.ports_n))
        return 1;
    log_msg(LOG_INFO, "filter: %s", filter);

    g_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (g_handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            log_msg(LOG_ERR, "access denied: run as Administrator");
        else if (err == ERROR_DRIVER_BLOCKED)
            log_msg(LOG_ERR, "WinDivert driver blocked (antivirus?)");
        else
            log_msg(LOG_ERR, "WinDivertOpen failed (error %lu)", err);
        return 1;
    }

    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_LENGTH,
                      WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_TIME,
                      WINDIVERT_PARAM_QUEUE_TIME_DEFAULT);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_SIZE,
                      WINDIVERT_PARAM_QUEUE_SIZE_MAX);

    InterlockedExchange(&g_running, 1);
    if (InterlockedCompareExchange(&g_stop, 0, 0))
    {
        log_msg(LOG_INFO, "stop requested before start, exiting");
        WinDivertClose(g_handle);
        g_handle = INVALID_HANDLE_VALUE;
        return 0;
    }
    start_ms = now_ms();
    log_msg(LOG_INFO, "%s v%s running%s, press Ctrl+C to stop",
            DBDPI_NAME, DBDPI_VERSION,
            g_cfg.dry_run ? " (dry-run)" : "");
    if (g_cfg.timeout_sec > 0)
        log_msg(LOG_INFO, "auto-exit in %d seconds", g_cfg.timeout_sec);

    for (;;)
    {
        WINDIVERT_IPHDR *iph = NULL;
        WINDIVERT_IPV6HDR *ip6h = NULL;
        WINDIVERT_TCPHDR *tcp = NULL;
        VOID *pdata = NULL;
        UINT plen = 0;
        bool ipv6, outbound;
        uint8_t src[16], dst[16];
        uint16_t sport, dport;
        uint64_t t = now_ms();

        /* timeout auto-exit */
        if (g_cfg.timeout_sec > 0 &&
            (t - start_ms) >= (uint64_t)g_cfg.timeout_sec * 1000)
        {
            log_msg(LOG_INFO, "timeout (%d sec) reached, exiting", g_cfg.timeout_sec);
            break;
        }

        if (!WinDivertRecv(g_handle, pkt, sizeof(pkt), &rlen, &addr))
        {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || g_running == 0)
                break;                      /* shutdown requested */
            log_msg(LOG_ERR, "WinDivertRecv failed (error %lu)", err);
            break;
        }
        if (!WinDivertHelperParsePacket(pkt, rlen, &iph, &ip6h, NULL, NULL,
                                        NULL, &tcp, NULL, &pdata, &plen,
                                        NULL, NULL) ||
            !tcp)
        {
            WinDivertSend(g_handle, pkt, rlen, NULL, &addr);
            continue;
        }
        ipv6 = (addr.IPv6 != 0) || (ip6h != NULL);
        outbound = (addr.Outbound != 0);
        if (ipv6)
        {
            memcpy(src, ip6h->SrcAddr, 16);
            memcpy(dst, ip6h->DstAddr, 16);
        }
        else
        {
            memcpy(src, &iph->SrcAddr, 4);
            memcpy(dst, &iph->DstAddr, 4);
        }
        sport = ntohs(tcp->SrcPort);
        dport = ntohs(tcp->DstPort);

        if (!outbound)
        {
            /* inbound SYN+ACK from our ports: autottl measurement */
            if (tcp->Syn && tcp->Ack && !tcp->Rst && plen == 0)
                handle_inbound_synack(pkt, rlen, &addr, tcp, src, dst,
                                      sport, dport, ipv6);
            WinDivertSend(g_handle, pkt, rlen, NULL, &addr);
        }
        else if (plen > 0 && tcp->Ack)
        {
            handle_outbound_data(g_handle, pkt, rlen, &addr, tcp,
                                 (const uint8_t *)pdata, plen,
                                 src, sport, dst, dport, ipv6);
        }
        else
        {
            if (tcp->Syn && !tcp->Ack)
            {
                /* Track the flow from its SYN: the SYN+ACK arrives before any
                 * data, so without this the autottl path measurement would
                 * find no connection and stay unknown. */
                conntrack_get_or_add(src, sport, dst, dport, ipv6 ? 6 : 4);

                if (g_cfg.prof.wsize)
                {
                    WINDIVERT_IPHDR *ih;
                    WINDIVERT_IPV6HDR *i6;
                    WINDIVERT_TCPHDR *t2;
                    if (WinDivertHelperParsePacket(pkt, rlen, &ih, &i6, NULL,
                                                   NULL, NULL, &t2, NULL, NULL,
                                                   NULL, NULL, NULL) && t2)
                    {
                        t2->Window = htons(g_cfg.prof.wsize);
                        WinDivertHelperCalcChecksums(pkt, rlen, &addr, 0);
                    }
                }
            }
            WinDivertSend(g_handle, pkt, rlen, NULL, &addr);
        }

        /* periodic maintenance */
        if (t - last_sweep > 30000)
        {
            last_sweep = t;
            conntrack_sweep();
        }
        /* periodic stats logging (every 60 sec) */
        if (t - last_stats > 60000)
        {
            last_stats = t;
            if (g_stats.pkt_total > 0)
                log_stats();
        }
        /* hostlist hot reload check (every 30 sec) */
        if (t - last_hostlist_check > 30000)
        {
            last_hostlist_check = t;
            hostlist_reload_if_changed(&g_cfg.hostlist);
            hostlist_reload_if_changed(&g_cfg.hostlist_exclude);
        }
    }

    log_stats();
    log_msg(LOG_INFO, "stopped");
    WinDivertClose(g_handle);
    g_handle = INVALID_HANDLE_VALUE;
    return 0;
}
