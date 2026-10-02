/* DBDPI - domain lists: whitelist / exclude, suffix (subdomain) matching.
 * Domains are stored reversed ("com.youtube") so that binary search can
 * efficiently handle suffix (subdomain) queries. */
#include "dbdpi.h"

#include <sys/stat.h>

static void str_lower(char *s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s += 32;
}

/* strip leading dots, trailing dots and whitespace; lowercase */
static void normalize(char *s)
{
    char *p = s, *end;

    while (*p == '.' || *p == ' ' || *p == '\t') p++;
    end = p + strlen(p);
    while (end > p && (end[-1] == '.' || end[-1] == ' ' ||
                       end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    *end = 0;
    memmove(s, p, (size_t)(end - p) + 1);
    str_lower(s);
}

/* reverse a domain label-by-label: "www.youtube.com" -> "com.youtube.www" */
static void reverse_domain(const char *src, char *dst, size_t cap)
{
    size_t len = strlen(src);
    size_t out = 0;
    int i = (int)len;
    while (i > 0 && out < cap - 1)
    {
        int start = i - 1;
        while (start > 0 && src[start - 1] != '.') start--;
        {
            int j;
            for (j = start; j < i && out < cap - 1; j++)
                dst[out++] = src[j];
        }
        if (start > 0 && out < cap - 1)
            dst[out++] = '.';
        i = start > 0 ? start - 1 : 0;
    }
    dst[out] = 0;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int hostlist_load(hostlist_t *hl, const char *path)
{
    FILE *f;
    char line[MAX_HOST * 2];
    struct _stat st;

    memset(hl, 0, sizeof(*hl));
    f = fopen(path, "rb");
    if (!f)
    {
        log_msg(LOG_ERR, "hostlist: cannot open %s (error %lu)", path, GetLastError());
        return -1;
    }
    while (fgets(line, sizeof(line), f))
    {
        char rev[MAX_HOST];
        char *hash;
        /* utf-8 BOM on first line */
        if (hl->n == 0 && (unsigned char)line[0] == 0xEF)
            memmove(line, line + 3, strlen(line + 3) + 1);
        hash = strchr(line, '#');
        if (hash)
            *hash = 0;
        normalize(line);
        if (!line[0])
            continue;
        if (hl->n == hl->cap)
        {
            size_t ncap = hl->cap ? hl->cap * 2 : 256;
            char **ni = realloc(hl->items, ncap * sizeof(char *));
            if (!ni)
            {
                fclose(f);
                return -1;
            }
            hl->items = ni;
            hl->cap = ncap;
        }
        reverse_domain(line, rev, sizeof(rev));
        hl->items[hl->n] = strdup(rev);
        if (!hl->items[hl->n])
            break;
        hl->n++;
    }
    fclose(f);

    /* sort for binary search */
    if (hl->n > 1)
        qsort(hl->items, hl->n, sizeof(char *), cmp_str);

    /* record mtime for hot reload */
    if (_stat(path, &st) == 0)
        hl->mtime = (uint64_t)st.st_mtime;
    hl->path = strdup(path);

    log_msg(LOG_INFO, "hostlist %s: %zu domains loaded", path, hl->n);
    return (int)hl->n;
}

/* Binary search: find the leftmost entry >= reversed host.
 * Then check if it's an exact match or a suffix match (dot boundary). */
bool hostlist_match(const hostlist_t *hl, const char *host)
{
    char rev[MAX_HOST];
    size_t rlen, lo, hi;

    if (!hl->n || !host || !host[0])
        return false;

    {
        char h[MAX_HOST];
        snprintf(h, sizeof(h), "%s", host);
        str_lower(h);
        reverse_domain(h, rev, sizeof(rev));
    }
    rlen = strlen(rev);

    /* binary search: find first entry >= rev */
    lo = 0;
    hi = hl->n;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(hl->items[mid], rev) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }

    /* check entries starting from lo: exact or prefix match */
    while (lo < hl->n)
    {
        const char *item = hl->items[lo];
        size_t ilen = strlen(item);

        if (strcmp(item, rev) == 0)
            return true;                        /* exact */

        /* item is a prefix of rev with dot boundary:
         * reversed "com.youtube" matches reversed "com.youtube.www" */
        if (ilen < rlen && rev[ilen] == '.' &&
            memcmp(item, rev, ilen) == 0)
            return true;

        /* if item doesn't even start with the same prefix, stop */
        if (strncmp(item, rev, ilen < rlen ? ilen : rlen) > 0)
            break;
        lo++;
    }
    return false;
}

bool hostlist_reload_if_changed(hostlist_t *hl)
{
    struct _stat st;
    hostlist_t fresh;

    if (!hl->path)
        return false;
    if (_stat(hl->path, &st) != 0)
        return false;
    if ((uint64_t)st.st_mtime == hl->mtime)
        return false;

    if (hostlist_load(&fresh, hl->path) < 0)
        return false;

    /* swap: free old, replace with fresh (which has its own path copy) */
    hostlist_free(hl);
    *hl = fresh;
    log_msg(LOG_INFO, "hostlist %s: reloaded (%zu domains)", hl->path, hl->n);
    return true;
}

void hostlist_free(hostlist_t *hl)
{
    size_t i;
    for (i = 0; i < hl->n; i++)
        free(hl->items[i]);
    free(hl->items);
    free(hl->path);
    memset(hl, 0, sizeof(*hl));
}
