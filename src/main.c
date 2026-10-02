/* DBDPI - main: CLI, presets, config file, service mode, selftest */
#include "dbdpi.h"

config_t g_cfg;
stats_t  g_stats;

static void prof_defaults(profile_t *p)
{
    memset(p, 0, sizeof(*p));
    p->mode = DESYNC_NONE;
    p->fooling = FOOL_NONE;
    p->fake_repeats = 1;
    p->badseq_delta = -100000;
    p->autottl_delta = 3;
    p->autottl_min = 3;
    p->autottl_max = 64;
    p->max_payload = 8192;
}

void config_defaults(void)
{
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.ports[0] = 80;
    g_cfg.ports[1] = 443;
    g_cfg.ports_n = 2;
    g_cfg.log_level = LOG_INFO;
    prof_defaults(&g_cfg.prof);
    memset(&g_stats, 0, sizeof(g_stats));
}

/* ------------------------------------------------------------ arg parsing */

static bool parse_ports(const char *val)
{
    char tmp[128];
    char *ctx, *tok;
    snprintf(tmp, sizeof(tmp), "%s", val);
    g_cfg.ports_n = 0;
    for (tok = strtok_s(tmp, ",", &ctx); tok && g_cfg.ports_n < MAX_PORTS;
         tok = strtok_s(NULL, ",", &ctx))
        g_cfg.ports[g_cfg.ports_n++] = (uint16_t)atoi(tok);
    return g_cfg.ports_n > 0;
}

static bool parse_marker(const char *tok, split_marker_t *m)
{
    if (!_stricmp(tok, "method"))   *m = SP_METHOD;
    else if (!_stricmp(tok, "host"))     *m = SP_HOST;
    else if (!_stricmp(tok, "endhost"))  *m = SP_ENDHOST;
    else if (!_stricmp(tok, "midsld"))   *m = SP_MIDSLD;
    else if (!_stricmp(tok, "sni"))      *m = SP_SNI;
    else if (!_stricmp(tok, "sniext"))   *m = SP_SNIEXT;
    else
        return false;
    return true;
}

static bool parse_split_pos(const char *val)
{
    char tmp[256];
    char *ctx, *tok;
    profile_t *p = &g_cfg.prof;
    snprintf(tmp, sizeof(tmp), "%s", val);
    p->split_pos_n = 0;
    for (tok = strtok_s(tmp, ",", &ctx); tok && p->split_pos_n < MAX_SPLIT_POS;
         tok = strtok_s(NULL, ",", &ctx))
    {
        split_pos_t *sp = &p->split_pos[p->split_pos_n];
        split_marker_t m;
        if (parse_marker(tok, &m))
        {
            sp->is_marker = true;
            sp->marker = m;
        }
        else
        {
            sp->is_marker = false;
            sp->value = atoi(tok);
        }
        p->split_pos_n++;
    }
    return p->split_pos_n > 0;
}

static bool parse_fooling(const char *val)
{
    char tmp[128];
    char *ctx, *tok;
    profile_t *p = &g_cfg.prof;
    p->fooling = FOOL_NONE;
    snprintf(tmp, sizeof(tmp), "%s", val);
    for (tok = strtok_s(tmp, ",", &ctx); tok; tok = strtok_s(NULL, ",", &ctx))
    {
        if (!_stricmp(tok, "badsum"))       p->fooling |= FOOL_BADSUM;
        else if (!_stricmp(tok, "badseq"))  p->fooling |= FOOL_BADSEQ;
        else if (!_stricmp(tok, "ttl"))     p->fooling |= FOOL_TTL;
        else if (!_stricmp(tok, "datanoack")) p->fooling |= FOOL_DATANOACK;
        else if (!_stricmp(tok, "none"))    p->fooling = FOOL_NONE;
        else return false;
    }
    return true;
}

static bool parse_autottl(const char *val, profile_t *p)
{
    int d = 3, mn = 3, mx = 64;
    if (sscanf(val, "%d:%d-%d", &d, &mn, &mx) != 3 &&
        sscanf(val, "%d", &d) != 1)
        return false;
    p->autottl = true;
    p->autottl_delta = d;
    p->autottl_min = mn;
    p->autottl_max = mx;
    return true;
}

static bool parse_mode(const char *val)
{
    profile_t *p = &g_cfg.prof;
    if (!_stricmp(val, "split") || !_stricmp(val, "split2"))
        p->mode = DESYNC_SPLIT;
    else if (!_stricmp(val, "multisplit"))   p->mode = DESYNC_MULTISPLIT;
    else if (!_stricmp(val, "disorder"))     p->mode = DESYNC_DISORDER;
    else if (!_stricmp(val, "fake"))         p->mode = DESYNC_FAKE;
    else if (!_stricmp(val, "fakedsplit"))   p->mode = DESYNC_FAKEDSPLIT;
    else if (!_stricmp(val, "none"))         p->mode = DESYNC_NONE;
    else return false;
    return true;
}

static void apply_preset(int n)
{
    profile_t *p = &g_cfg.prof;
    prof_defaults(p);
    switch (n)
    {
    case 1: /* universal multisplit in the middle of SLD */
        p->mode = DESYNC_MULTISPLIT;
        p->split_pos_n = 1;
        p->split_pos[0].is_marker = true;
        p->split_pos[0].marker = SP_MIDSLD;
        break;
    case 2: /* split at method and host */
        p->mode = DESYNC_MULTISPLIT;
        p->split_pos_n = 3;
        p->split_pos[0].is_marker = true; p->split_pos[0].marker = SP_METHOD;
        p->split_pos[1].is_marker = true; p->split_pos[1].marker = SP_HOST;
        p->split_pos[2].is_marker = true; p->split_pos[2].marker = SP_ENDHOST;
        break;
    case 3: /* out of order */
        p->mode = DESYNC_DISORDER;
        p->split_pos_n = 1;
        p->split_pos[0].is_marker = true; p->split_pos[0].marker = SP_MIDSLD;
        break;
    case 4: /* fake + split */
        p->mode = DESYNC_FAKEDSPLIT;
        p->split_pos_n = 1;
        p->split_pos[0].is_marker = true; p->split_pos[0].marker = SP_MIDSLD;
        p->fake_gen = true;
        p->fooling = FOOL_BADSUM | FOOL_BADSEQ;
        break;
    case 5: /* fake only */
        p->mode = DESYNC_FAKE;
        p->fake_gen = true;
        p->fooling = FOOL_BADSUM | FOOL_BADSEQ;
        p->fake_repeats = 2;
        break;
    case 6: /* disorder at SNI extension */
        p->mode = DESYNC_DISORDER;
        p->split_pos_n = 1;
        p->split_pos[0].is_marker = true; p->split_pos[0].marker = SP_SNIEXT;
        break;
    default:
        log_msg(LOG_ERR, "unknown preset %d", n);
        break;
    }
}

static void usage(void)
{
    printf(
"%s (dbdpi) v%s - DPI/TSPU desync tool for Windows\n\n"
"Usage: dbdpi.exe [options]\n",
        DBDPI_NAME, DBDPI_VERSION);
    printf(
"  --wf-tcp=80,443          TCP ports to intercept (default 80,443)\n"
"  --dpi-desync=MODE        split | multisplit | disorder | fake | fakedsplit\n"
"  --split-pos=POS[,POS]    position: number or marker\n"
"                           markers: method, host, endhost, midsld, sni, sniext\n"
"  --hostlist=FILE          process only domains from file (+ subdomains)\n"
"  --hostlist-exclude=FILE  never process domains from file\n"
"  --fake-tls=FILE          fake ClientHello payload from file (raw or hex)\n"
"  --fake-http=FILE         fake HTTP payload from file\n"
"  --fake-gen               built-in browser-like ClientHello generator\n"
"  --fooling=LIST           fake invalidation: badsum,badseq,ttl,datanoack,none\n"
"  --ttl=N                  fixed fake TTL (with --fooling=ttl)\n"
"  --autottl=D:M-X          auto TTL from path length (default 3:3-64)\n"
"  --repeats=N              send N copies of each fake\n"
"  --badseq=N               seq delta for badseq fakes (default -100000)\n"
"  --hostcase               shuffle case of HTTP Host header\n"
"  --hosttab                replace space after Host: with tab\n"
"  --methodeol              prepend CRLF before HTTP method (seqovl)\n"
"  --wsize=N                rewrite TCP window in outbound SYN\n"
"  --max-payload=N          skip segments bigger than N (default 8192)\n"
"  --preset=N               ready strategy: 1..6 (see README)\n"
"  --config=FILE            read options from file (same format as service.args)\n"
"  --dry-run                log desync decisions without injecting packets\n"
"  --timeout=N              auto-exit after N seconds (useful for blockcheck)\n"
"  --log=FILE               also log to file\n"
"  --debug                  verbose logging\n"
"  --service-run=ARGFILE    run as Windows service with args from file\n"
"  --install-service=ARGFILE  install service DBDPI (as admin)\n"
"  --remove-service         remove service DBDPI (as admin)\n"
"  --selftest               run built-in tests (parsers, lists, desync)\n"
"  --version | --help\n");
}

/* value of "--key=val" or NULL */
static const char *arg_val(const char *arg, const char *key)
{
    size_t kl = strlen(key);
    if (strncmp(arg, key, kl) != 0)
        return NULL;
    if (arg[kl] == '=')
        return arg + kl + 1;
    return NULL;
}

/* returns: 0 = ok, 1 = error, 2 = exit (help/version/selftest shown) */
int config_parse(int argc, char **argv)
{
    int i;
    bool preset_seen = false;
    for (i = 1; i < argc; i++)
    {
        const char *a = argv[i];
        const char *v;
        if (!strcmp(a, "--help") || !strcmp(a, "-h"))
            { usage(); return 2; }
        else if (!strcmp(a, "--version"))
            { printf("%s (dbdpi) v%s\n", DBDPI_NAME, DBDPI_VERSION); return 2; }
        else if (!strcmp(a, "--debug"))
            g_cfg.log_level = LOG_DEBUG;
        else if (!strcmp(a, "--fake-gen"))
            g_cfg.prof.fake_gen = true;
        else if (!strcmp(a, "--hostcase"))
            g_cfg.prof.hostcase = true;
        else if (!strcmp(a, "--hosttab"))
            g_cfg.prof.hosttab = true;
        else if (!strcmp(a, "--methodeol"))
            g_cfg.prof.methodeol = true;
        else if (!strcmp(a, "--dry-run"))
            g_cfg.dry_run = true;
        else if (!strcmp(a, "--selftest"))
            return 3;
        else if ((v = arg_val(a, "--wf-tcp")) != NULL) parse_ports(v);
        else if ((v = arg_val(a, "--dpi-desync")) != NULL)
        {
            if (!parse_mode(v))
                { fprintf(stderr, "bad --dpi-desync: %s\n", v); return 1; }
        }
        else if ((v = arg_val(a, "--split-pos")) != NULL)
        {
            if (!parse_split_pos(v))
                { fprintf(stderr, "bad --split-pos: %s\n", v); return 1; }
        }
        else if ((v = arg_val(a, "--hostlist")) != NULL)
            g_cfg.hostlist_path = strdup(v);
        else if ((v = arg_val(a, "--hostlist-exclude")) != NULL)
            g_cfg.hostlist_exclude_path = strdup(v);
        else if ((v = arg_val(a, "--fake-tls")) != NULL)
            { g_cfg.prof.fake_tls_path = strdup(v); g_cfg.prof.fake_from_file = true; }
        else if ((v = arg_val(a, "--fake-http")) != NULL)
            g_cfg.prof.fake_http_path = strdup(v);
        else if ((v = arg_val(a, "--fooling")) != NULL)
        {
            if (!parse_fooling(v))
                { fprintf(stderr, "bad --fooling: %s\n", v); return 1; }
        }
        else if ((v = arg_val(a, "--ttl")) != NULL)
            g_cfg.prof.ttl = atoi(v);
        else if ((v = arg_val(a, "--autottl")) != NULL)
        {
            if (!parse_autottl(v, &g_cfg.prof))
                { fprintf(stderr, "bad --autottl: %s\n", v); return 1; }
        }
        else if ((v = arg_val(a, "--repeats")) != NULL)
            g_cfg.prof.fake_repeats = atoi(v);
        else if ((v = arg_val(a, "--badseq")) != NULL)
            g_cfg.prof.badseq_delta = atoi(v);
        else if ((v = arg_val(a, "--wsize")) != NULL)
            g_cfg.prof.wsize = (uint16_t)atoi(v);
        else if ((v = arg_val(a, "--max-payload")) != NULL)
            g_cfg.prof.max_payload = (uint32_t)atoi(v);
        else if ((v = arg_val(a, "--preset")) != NULL)
            { apply_preset(atoi(v)); preset_seen = true; }
        else if ((v = arg_val(a, "--log")) != NULL)
            g_cfg.log_path = strdup(v);
        else if ((v = arg_val(a, "--timeout")) != NULL)
            g_cfg.timeout_sec = atoi(v);
        else if (arg_val(a, "--service-run") != NULL)
            ;   /* handled by caller (service_run_main) */
        else if (arg_val(a, "--config") != NULL)
            ;   /* handled by caller (load_config_file) */
        else
            { fprintf(stderr, "unknown option: %s (see --help)\n", a); return 1; }
    }
    if (!preset_seen && g_cfg.prof.mode == DESYNC_NONE)
        log_msg(LOG_INFO, "no strategy configured: passthrough mode");
    if ((g_cfg.prof.mode == DESYNC_FAKE ||
         g_cfg.prof.mode == DESYNC_FAKEDSPLIT) &&
        g_cfg.prof.fooling == FOOL_NONE)
        log_msg(LOG_ERR, "warning: fake packets without --fooling are not "
                         "invalidated and can reach the server");
    if ((g_cfg.prof.fooling & FOOL_TTL) && !g_cfg.prof.autottl &&
        g_cfg.prof.ttl <= 0)
        log_msg(LOG_ERR, "warning: --fooling=ttl without --ttl or --autottl: "
                         "no TTL for fakes, they will be skipped");
    if (g_cfg.dry_run)
        log_msg(LOG_INFO, "dry-run mode: packets will be logged but not modified");
    return 0;
}

/* ------------------------------------------------------------- config file */

/* Load options from a config file. Each line is an argument (same format as
 * service.args). The config file is loaded before the rest of the CLI, so
 * command-line flags override. */
static int load_config_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    char line[4096];
    char **args;
    int argc = 0, rc;

    if (!f)
    {
        fprintf(stderr, "dbdpi: cannot open config file %s (error %lu)\n",
                path, GetLastError());
        return 1;
    }
    {
        size_t n = fread(line, 1, sizeof(line) - 1, f);
        if (n == sizeof(line) - 1 && !feof(f))
            fprintf(stderr, "dbdpi: config file %s too long, truncated\n", path);
        fclose(f);
        line[n] = 0;
    }
    args = tokenize_args(line, &argc);
    rc = config_parse(argc, args);
    if (rc == 1)
        return 1;
    return 0;
}

/* ------------------------------------------------------------- app startup */

/* One-time setup shared by the console and the service run: logging, domain
 * lists, connection tracking. Returns non-zero on fatal error. */
static int app_init(void)
{
    log_init(g_cfg.log_path, g_cfg.log_level);
    if (g_cfg.hostlist_path &&
        hostlist_load(&g_cfg.hostlist, g_cfg.hostlist_path) < 0)
        return 1;
    if (g_cfg.hostlist_exclude_path &&
        hostlist_load(&g_cfg.hostlist_exclude, g_cfg.hostlist_exclude_path) < 0)
        return 1;
    conntrack_init();
    return 0;
}

/* ---------------------------------------------------------------- service */

static SERVICE_STATUS g_svc_status;
static SERVICE_STATUS_HANDLE g_svc_handle;
static int g_worker_rc = 0;

static void svc_report(DWORD state, DWORD wait)
{
    g_svc_status.dwCurrentState = state;
    g_svc_status.dwWaitHint = wait;
    g_svc_status.dwCheckPoint++;
    SetServiceStatus(g_svc_handle, &g_svc_status);
}

static DWORD WINAPI svc_ctrl_static(DWORD ctrl, DWORD type, LPVOID data, LPVOID ctx)
{
    (void)type; (void)data; (void)ctx;
    switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        svc_report(SERVICE_STOP_PENDING, 5000);
        divert_shutdown();
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void WINAPI svc_main(DWORD argc, LPWSTR *argv)
{
    static HANDLE thread;
    (void)argc; (void)argv;
    g_svc_handle = RegisterServiceCtrlHandlerExW(L"DBDPI",
                    (LPHANDLER_FUNCTION_EX)svc_ctrl_static, NULL);
    if (!g_svc_handle)
        return;
    g_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    svc_report(SERVICE_START_PENDING, 2000);

    thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)(void *)divert_run, NULL, 0, NULL);
    if (!thread)
    {
        svc_report(SERVICE_STOPPED, 0);
        return;
    }
    svc_report(SERVICE_RUNNING, 0);
    WaitForSingleObject(thread, INFINITE);
    GetExitCodeThread(thread, (LPDWORD)&g_worker_rc);
    CloseHandle(thread);
    svc_report(SERVICE_STOPPED, 0);
}

/* Splits the line in place: tokens are NUL-terminated inside `line` itself, so
 * no extra buffer is needed (and nothing can overflow). Quoting is honored
 * anywhere in a token, so paths like --log="C:\Program Files\x.log" work.
 * argv[0] is a dummy program name because config_parse() expects real argv
 * layout. */
char **tokenize_args(char *line, int *argc_out)
{
    static char *argvs[65];
    static char prog[] = "dbdpi";
    int argc = 0;
    char *p = line, *w;

    argvs[argc++] = prog;
    while (*p && argc < 64)
    {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        argvs[argc++] = w = p;      /* token is compacted over the raw text */
        while (*p && !strchr(" \t\r\n", *p))
        {
            if (*p == '"')
            {
                p++;
                while (*p && *p != '"')
                    *w++ = *p++;
                if (*p == '"')
                    p++;
                continue;
            }
            *w++ = *p++;
        }
        if (*p)
            p++;                    /* step over the delimiter */
        *w = 0;
    }
    *argc_out = argc;
    return argvs;
}

static int install_service(const char *argsfile)
{
    SC_HANDLE scm, svc;
    char path[MAX_PATH + 256];
    char quoted[2 * MAX_PATH + 128];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    snprintf(quoted, sizeof(quoted), "\"%s\" --service-run=\"%s\"", path, argsfile);
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm)
    {
        log_msg(LOG_ERR, "OpenSCManager failed (error %lu) - run as admin", GetLastError());
        return 1;
    }
    svc = CreateServiceA(scm, "DBDPI", "Dice Bypass DPI (dbdpi)",
                         SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                         quoted, NULL, NULL, NULL, NULL, NULL);
    if (!svc)
    {
        log_msg(LOG_ERR, "CreateService failed (error %lu)", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    log_msg(LOG_INFO, "service installed: %s", quoted);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int remove_service(void)
{
    SC_HANDLE scm, svc;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        log_msg(LOG_ERR, "OpenSCManager failed (error %lu) - run as admin", GetLastError());
        return 1;
    }
    svc = OpenServiceA(scm, "DBDPI", DELETE);
    if (!svc)
    {
        log_msg(LOG_ERR, "service DBDPI not found (error %lu)", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    if (!DeleteService(svc))
        log_msg(LOG_ERR, "DeleteService failed (error %lu)", GetLastError());
    else
        log_msg(LOG_INFO, "service DBDPI removed");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

/* --service-run=ARGFILE */
int service_run_main(const char *argsfile)
{
    FILE *f = fopen(argsfile, "rb");
    char line[4096];
    char **args;
    int argc = 0, rc;
    SERVICE_TABLE_ENTRYA table[2];

    line[0] = 0;
    if (f)
    {
        size_t n = fread(line, 1, sizeof(line) - 1, f);
        if (n == sizeof(line) - 1 && !feof(f))
            fprintf(stderr, "dbdpi: args file %s too long, truncated\n", argsfile);
        fclose(f);
        line[n] = 0;
    }
    else
        fprintf(stderr, "dbdpi: cannot open args file %s (error %lu)\n",
                argsfile, GetLastError());

    /* connect to SCM first; parse config in worker-independent place */
    args = tokenize_args(line, &argc);
    /* re-run config parsing now (before dispatcher) is fine: parse happens
     * once here; svc_main only runs the loop */
    rc = config_parse(argc, args);
    if (rc == 1)
        return 1;
    if (app_init())
        return 1;
    log_msg(LOG_INFO, "service: %d args from %s, desync mode %d, %d split pos",
            argc, argsfile, (int)g_cfg.prof.mode, g_cfg.prof.split_pos_n);

    table[0].lpServiceName = "DBDPI";
    table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTIONA)svc_main;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherA(table))
    {
        log_msg(LOG_ERR, "StartServiceCtrlDispatcher failed (error %lu) "
                         "--service-run only works from SCM", GetLastError());
        return 1;
    }
    return g_worker_rc;
}

/* ---------------------------------------------------------------- main run */

static BOOL WINAPI console_ctrl(DWORD type)
{
    (void)type;
    log_msg(LOG_INFO, "stopping...");
    divert_shutdown();
    return TRUE;
}

static int run_main(void)
{
    int rc;
    if (app_init())
        return 1;
    SetConsoleCtrlHandler(console_ctrl, TRUE);
    rc = divert_run();
    log_close();
    return rc;
}

int main(int argc, char **argv)
{
    int rc;
    const char *svcargs = NULL;
    const char *cfgfile = NULL;
    bool do_install = false, do_remove = false;

    config_defaults();

    /* first pass: extract --service-run, --install-service, --remove-service,
     * --config before general parsing */
    for (rc = 1; rc < argc; rc++)
    {
        const char *v;
        if ((v = arg_val(argv[rc], "--service-run")) != NULL)
            { svcargs = v; break; }
        if ((v = arg_val(argv[rc], "--install-service")) != NULL)
            { svcargs = v; do_install = true; break; }
        if (!strcmp(argv[rc], "--remove-service"))
            { do_remove = true; break; }
        if ((v = arg_val(argv[rc], "--config")) != NULL)
            cfgfile = v;
    }
    if (do_remove)
        return remove_service();
    if (do_install && svcargs)
        return install_service(svcargs);
    /* In service mode the whole configuration comes from the args file written
     * by service_install.cmd, so argv is not parsed here. */
    if (svcargs)
        return service_run_main(svcargs);

    config_defaults();

    /* load config file first (CLI overrides) */
    if (cfgfile)
    {
        rc = load_config_file(cfgfile);
        if (rc)
            return 1;
    }

    rc = config_parse(argc, argv);
    if (rc == 1)
        return 1;
    if (rc == 2)
        return 0;
    if (rc == 3)
        return selftest();

    return run_main();
}
