/* DBDPI - TLS record / ClientHello parsing with SNI extraction */
#include "dbdpi.h"

#define TLS_CONTENT_HANDSHAKE 0x16
#define TLS_HS_CLIENT_HELLO   0x01
#define TLS_EXT_SERVER_NAME   0x0000

static bool rd16(const uint8_t *p, size_t avail, uint16_t *out)
{
    if (avail < 2)
        return false;
    *out = (uint16_t)((p[0] << 8) | p[1]);
    return true;
}

/* Parse TLS ClientHello (one record). All offsets are relative to payload. */
bool tls_parse_client_hello(const uint8_t *p, size_t len, tls_info_t *ti)
{
    size_t off, ext_end;
    uint16_t rec_len, ext_all_len;
    uint32_t hs_len;
    uint8_t sid_len, comp_len;
    uint16_t cs_len;

    memset(ti, 0, sizeof(*ti));
    ti->sni_off = -1;
    ti->sni_ext_off = -1;
    ti->hello_end = -1;

    if (len < 6 || p[0] != TLS_CONTENT_HANDSHAKE)
        return false;
    if (p[1] != 0x03)                       /* major version */
        return false;
    if (!rd16(p + 3, len - 3, &rec_len))
        return false;
    if ((size_t)rec_len + 5 > len)          /* record must be fully here */
        return false;
    if (p[5] != TLS_HS_CLIENT_HELLO)
        return false;

    hs_len = ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 8) | p[8];
    if ((size_t)hs_len + 9 > len)           /* handshake must be fully here */
        return false;
    ti->is_client_hello = true;
    ti->hello_end = (int)(9 + hs_len);

    off = 9;                                /* client version */
    off += 2 + 32;                          /* version + random */
    if (off + 1 > (size_t)ti->hello_end)
        return false;
    sid_len = p[off];                       /* session id */
    off += 1 + sid_len;
    if (off + 2 > (size_t)ti->hello_end)
        return false;
    cs_len = (uint16_t)((p[off] << 8) | p[off + 1]);
    off += 2 + cs_len;                      /* cipher suites */
    if (off + 1 > (size_t)ti->hello_end)
        return false;
    comp_len = p[off];                      /* compression methods */
    off += 1 + comp_len;
    if (off + 2 > (size_t)ti->hello_end)
        return false;
    if (!rd16(p + off, (size_t)ti->hello_end - off, &ext_all_len))
        return false;
    off += 2;
    if ((size_t)ext_all_len + off > (size_t)ti->hello_end)
        return false;

    /* walk extensions */
    ext_end = off + ext_all_len;
    while (off + 4 <= ext_end)
    {
        uint16_t ext_type, ext_len;
        if (!rd16(p + off, (size_t)ti->hello_end - off, &ext_type))
            break;
        if (!rd16(p + off + 2, ext_end - off - 2, &ext_len))
            break;
        if (off + 4 + ext_len > ext_end)
            break;
        if (ext_type == TLS_EXT_SERVER_NAME && ti->sni_off < 0)
        {
            size_t e = off + 4;             /* extension data */
            size_t e_end = e + ext_len;
            uint16_t list_len;
            ti->sni_ext_off = (int)off;
            if (e + 2 <= e_end &&
                rd16(p + e, e_end - e, &list_len) &&
                list_len == ext_len - 2 &&
                e + 2 + 1 + 2 <= e_end &&
                p[e + 2] == 0)              /* name type: host_name */
            {
                uint16_t name_len;
                if (rd16(p + e + 3, e_end - e - 3, &name_len) &&
                    e + 5 + name_len <= e_end)
                {
                    ti->sni_off = (int)(e + 5);
                    if (name_len < MAX_HOST)
                    {
                        memcpy(ti->sni, p + ti->sni_off, name_len);
                        ti->sni[name_len] = 0;
                    }
                }
            }
        }
        off += 4 + ext_len;
    }
    return true;
}
