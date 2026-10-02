/* DBDPI - HTTP request detection, Host extraction */
#include "dbdpi.h"

static const char *methods[] =
{
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
};

bool http_parse_request(const uint8_t *p, size_t len, http_info_t *hi)
{
    size_t i, m, line = 0;
    bool found = false;

    memset(hi, 0, sizeof(*hi));
    if (len < 16 || len > 16384)
        return false;

    for (m = 0; m < sizeof(methods) / sizeof(methods[0]); m++)
    {
        size_t ml = strlen(methods[m]);
        if (len > ml && memcmp(p, methods[m], ml) == 0 && p[ml] == ' ')
        {
            hi->method_end_off = (int)ml;
            found = true;
            break;
        }
    }
    if (!found)
        return false;

    /* find header area end */
    for (i = 0; i + 1 < len; i++)
    {
        if (p[i] == '\r' && p[i + 1] == '\n')
        {
            if (i + 3 < len && p[i + 2] == '\r' && p[i + 3] == '\n')
                break;
            if (line++ > 32)
                break;
            i++;    /* skip \n */
        }
    }
    if (i + 3 >= len)
        return false;   /* no complete header block */

    /* scan headers for Host */
    {
        size_t pos = (size_t)hi->method_end_off + 1;
        while (pos + 2 < len)
        {
            size_t eol;
            char name[16];
            size_t name_len = 0;

            for (eol = pos; eol + 1 < len && !(p[eol] == '\r' && p[eol + 1] == '\n'); eol++) {}
            if (eol + 1 >= len)
                break;
            if (eol == pos)     /* empty line - end */
                break;
            while (pos + name_len < eol && p[pos + name_len] != ':' &&
                   name_len + 1 < sizeof(name))
            {
                char c = (char)p[pos + name_len];
                if (c >= 'A' && c <= 'Z') c += 32;
                name[name_len++] = c;
            }
            name[name_len] = 0;
            if (pos + name_len < eol && p[pos + name_len] == ':' &&
                strcmp(name, "host") == 0)
            {
                size_t vs = pos + name_len + 1, ve;
                while (vs < eol && (p[vs] == ' ' || p[vs] == '\t')) vs++;
                ve = eol;
                while (ve > vs && (p[ve - 1] == ' ' || p[ve - 1] == '\t')) ve--;
                if (ve > vs && ve - vs < MAX_HOST)
                {
                    memcpy(hi->host, p + vs, ve - vs);
                    hi->host[ve - vs] = 0;
                    hi->host_off = (int)vs;
                    hi->host_len = (int)(ve - vs);
                }
            }
            pos = eol + 2;
        }
    }
    hi->is_request = true;
    return true;
}
