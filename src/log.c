/* DBDPI - logging */
#include "dbdpi.h"

static int      level = LOG_INFO;
static FILE    *flog = NULL;
static CRITICAL_SECTION lock;
static INIT_ONCE lock_once = INIT_ONCE_STATIC_INIT;

/* log_msg() is called from paths that never reach log_init() (service
 * install/remove, --service-run, plain start), so the lock is created on
 * first use instead of in log_init(). */
static BOOL CALLBACK lock_create(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&lock);
    return TRUE;
}

static void lock_ensure(void)
{
    InitOnceExecuteOnce(&lock_once, lock_create, NULL, NULL);
}

void log_init(const char *path, int lvl)
{
    lock_ensure();
    level = lvl;
    if (path)
    {
        flog = fopen(path, "ab");
        if (!flog)
            fprintf(stderr, "dbdpi: cannot open log file %s (error %lu)\n",
                    path, GetLastError());
    }
}

void log_close(void)
{
    if (flog) { fclose(flog); flog = NULL; }
}

void log_msg(int lvl, const char *fmt, ...)
{
    va_list ap;
    char stamp[64];
    SYSTEMTIME st;
    FILE *out[2];
    int i, nout = 0;

    if (lvl > level)
        return;

    lock_ensure();
    out[nout++] = stderr;
    if (flog)
        out[nout++] = flog;

    GetLocalTime(&st);
    snprintf(stamp, sizeof(stamp), "%04u-%02u-%02u %02u:%02u:%02u.%03u ",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    EnterCriticalSection(&lock);
    for (i = 0; i < nout; i++)
    {
        fprintf(out[i], "%s", stamp);
        va_start(ap, fmt);
        vfprintf(out[i], fmt, ap);
        va_end(ap);
        fputc('\n', out[i]);
        fflush(out[i]);
    }
    LeaveCriticalSection(&lock);
}
