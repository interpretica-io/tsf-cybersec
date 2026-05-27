/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief objdump TAPI
 *
 * Implementation of the @c objdump TAPI and of the checks built on its
 * disassembly.
 */

#define TE_LGR_USER "TAPI OBJDUMP"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_kvpair.h"
#include "te_str.h"
#include "te_string.h"

#include "tapi_devtool_run.h"
#include "tapi_objdump.h"

struct tapi_objdump_app {
    /** objdump job. */
    tapi_devtool_run run;
};

const char *const tapi_objdump_default_banned[] = {
    /* No bound on what they write. */
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    /* A bound that is easy to get wrong, and silent truncation. */
    "strncpy",
    "strncat",
    /* A string handed to a shell. */
    "system",
    "popen",
    "execlp",
    "execvp",
    /* Predictable randomness where randomness is the point. */
    "rand",
    "srand",
    /* Temporary files with a name an attacker can guess. */
    "tmpnam",
    "tempnam",
    "mktemp",
    NULL,
};

const tapi_objdump_opt tapi_objdump_default_opt = {
    .toolchain   = NULL,
    .objdump     = NULL,
    .path        = NULL,
    .disassemble = true,
    .demangle    = true,
    .wide        = true,
};

static const tapi_job_opt_bind objdump_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_BOOL("-d", tapi_objdump_opt, disassemble),
    TAPI_JOB_OPT_BOOL("-D", tapi_objdump_opt, disassemble_all),
    TAPI_JOB_OPT_STRING("--disassemble=", true, tapi_objdump_opt, symbol),
    TAPI_JOB_OPT_BOOL("-T", tapi_objdump_opt, dynamic_symbols),
    TAPI_JOB_OPT_BOOL("-t", tapi_objdump_opt, symbols),
    TAPI_JOB_OPT_BOOL("-r", tapi_objdump_opt, relocs),
    TAPI_JOB_OPT_BOOL("-R", tapi_objdump_opt, dynamic_relocs),
    TAPI_JOB_OPT_BOOL("-h", tapi_objdump_opt, section_headers),
    TAPI_JOB_OPT_BOOL("-f", tapi_objdump_opt, file_headers),
    TAPI_JOB_OPT_BOOL("-C", tapi_objdump_opt, demangle),
    TAPI_JOB_OPT_BOOL("-w", tapi_objdump_opt, wide),
    TAPI_JOB_OPT_STRING("-j", false, tapi_objdump_opt, section),
    TAPI_JOB_OPT_STRING(NULL, false, tapi_objdump_opt, path)
);

/** Work out which objdump to run, appending to @p dest when built. */
static const char *
objdump_program(const tapi_objdump_opt *opt, te_string *dest)
{
    if (opt->objdump != NULL)
        return opt->objdump;

    if (opt->toolchain != NULL && opt->toolchain->cross_compile != NULL)
    {
        te_string_append(dest, "%sobjdump", opt->toolchain->cross_compile);
        return dest->ptr;
    }

    return "objdump";
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_create(tapi_job_factory_t *factory, const tapi_objdump_opt *opt,
                    tapi_objdump_app **app)
{
    te_string program = TE_STRING_INIT;
    tapi_objdump_app *result;
    te_errno rc;

    if (opt->path == NULL)
    {
        ERROR("Path of the binary to look into is not set");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    result = TE_ALLOC(sizeof(*result));
    result->run = (tapi_devtool_run)TAPI_DEVTOOL_RUN_INIT;

    rc = tapi_devtool_run_init(&result->run, factory, "objdump",
                               objdump_program(opt, &program), objdump_binds,
                               opt, opt->workdir);
    te_string_free(&program);

    if (rc != 0)
    {
        free(result);
        return rc;
    }

    *app = result;

    return 0;
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_start(tapi_objdump_app *app)
{
    return tapi_devtool_run_start(&app->run);
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_wait(tapi_objdump_app *app, int timeout_ms)
{
    te_errno rc;

    rc = tapi_devtool_run_wait(&app->run, timeout_ms);
    if (rc != 0)
        return rc;

    return tapi_devtool_run_check(&app->run);
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_kill(tapi_objdump_app *app, int signum)
{
    return tapi_devtool_run_kill(&app->run, signum);
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_stop(tapi_objdump_app *app)
{
    return tapi_devtool_run_stop(&app->run);
}

/* See description in tapi_objdump.h */
void
tapi_objdump_get_output(const tapi_objdump_app *app,
                        tapi_devtool_output *output)
{
    tapi_devtool_run_get_output(&app->run, output);
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_destroy(tapi_objdump_app *app)
{
    te_errno rc;

    if (app == NULL)
        return 0;

    rc = tapi_devtool_run_fini(&app->run);
    free(app);

    return rc;
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_do(tapi_job_factory_t *factory, const tapi_objdump_opt *opt,
                int timeout_ms, tapi_objdump_app **app)
{
    te_errno rc;

    rc = tapi_objdump_create(factory, opt, app);
    if (rc != 0)
        return rc;

    rc = tapi_objdump_start(*app);
    if (rc != 0)
        return rc;

    return tapi_objdump_wait(*app, timeout_ms);
}

/**
 * Read the function name out of a disassembly header line.
 *
 * Those lines look like @c "0000000000001149 <main>:" and are the only
 * thing that says which function the lines below belong to.
 */
static bool
objdump_function_header(const char *line, te_string *name)
{
    const char *open_bracket;
    const char *close_bracket;
    const char *p = line;

    while (*p == ' ' || *p == '\t')
        p++;

    if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
        return false;

    open_bracket = strchr(p, '<');
    if (open_bracket == NULL)
        return false;

    close_bracket = strchr(open_bracket, '>');
    if (close_bracket == NULL || close_bracket[1] != ':')
        return false;

    te_string_reset(name);
    te_string_append(name, "%.*s", (int)(close_bracket - open_bracket - 1),
                     open_bracket + 1);

    return true;
}

/**
 * Read the symbol an instruction refers to.
 *
 * It is the last @c <...> of the line. The decorations are stripped:
 * @c "<strcpy@plt>" and @c "<strcpy+0x4>" are both @c strcpy.
 */
static bool
objdump_referenced_symbol(const char *line, te_string *symbol)
{
    const char *open_bracket = strrchr(line, '<');
    const char *close_bracket;
    const char *end;

    if (open_bracket == NULL)
        return false;

    close_bracket = strchr(open_bracket, '>');
    if (close_bracket == NULL)
        return false;

    end = close_bracket;
    for (const char *p = open_bracket + 1; p < close_bracket; p++)
    {
        if (*p == '@' || *p == '+')
        {
            end = p;
            break;
        }
    }

    if (end == open_bracket + 1)
        return false;

    te_string_reset(symbol);
    te_string_append(symbol, "%.*s", (int)(end - open_bracket - 1),
                     open_bracket + 1);

    return true;
}

/* See description in tapi_objdump.h */
te_errno
tapi_objdump_check_banned(tapi_job_factory_t *factory,
                          const tapi_objdump_opt *opt,
                          const char *const *banned, int timeout_ms,
                          tapi_cybersec_report *report)
{
    tapi_objdump_opt effective = *opt;
    tapi_objdump_app *app = NULL;
    tapi_devtool_output output;
    te_string function = TE_STRING_INIT;
    te_string symbol = TE_STRING_INIT;
    te_kvpair_h seen;
    char *text = NULL;
    char *line;
    char *saveptr = NULL;
    te_errno rc;

    if (banned == NULL)
        banned = tapi_objdump_default_banned;

    effective.disassemble = true;

    te_kvpair_init(&seen);

    rc = tapi_objdump_do(factory, &effective, timeout_ms, &app);
    if (rc != 0)
        goto out;

    tapi_objdump_get_output(app, &output);
    text = TE_STRDUP(output.out);

    for (line = strtok_r(text, "\n", &saveptr);
         line != NULL;
         line = strtok_r(NULL, "\n", &saveptr))
    {
        size_t i;

        if (objdump_function_header(line, &function))
            continue;

        if (!objdump_referenced_symbol(line, &symbol))
            continue;

        for (i = 0; banned[i] != NULL; i++)
        {
            te_string key = TE_STRING_INIT;

            if (strcmp(symbol.ptr, banned[i]) != 0)
                continue;

            /*
             * One finding per (function, callee): a loop that calls
             * strcpy ten times is one place to fix, not ten.
             */
            te_string_append(&key, "%s|%s", te_string_value(&function),
                             banned[i]);
            if (te_kvpairs_get_nth(&seen, key.ptr, 0) == NULL)
            {
                te_string subject = TE_STRING_INIT;

                te_kvpair_push(&seen, key.ptr, "1");
                te_string_append(&subject, "%s:%s", effective.path,
                                 banned[i]);
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                         "binary.banned-call", subject.ptr,
                                         "referenced from %s",
                                         function.len != 0 ?
                                             te_string_value(&function) :
                                             "an unnamed location");
                te_string_free(&subject);
            }
            te_string_free(&key);
            break;
        }
    }

out:
    tapi_objdump_destroy(app);
    te_kvpair_fini(&seen);
    te_string_free(&function);
    te_string_free(&symbol);
    free(text);

    return rc;
}

/* See description in tapi_objdump.h */
bool
tapi_objdump_extract_function(const char *text, const char *symbol,
                              te_string *dest)
{
    te_string header = TE_STRING_INIT;
    te_string name = TE_STRING_INIT;
    const char *line = text;
    bool inside = false;
    bool found = false;

    te_string_append(&header, "<%s>:", symbol);

    while (line != NULL && *line != '\0')
    {
        const char *eol = strchr(line, '\n');
        size_t len = (eol != NULL) ? (size_t)(eol - line) : strlen(line);
        te_string current = TE_STRING_INIT;

        te_string_append(&current, "%.*s", (int)len, line);

        if (objdump_function_header(current.ptr, &name))
        {
            if (inside)
            {
                te_string_free(&current);
                break;
            }
            inside = (strcmp(name.ptr, symbol) == 0);
            found = found || inside;
        }

        if (inside)
            te_string_append(dest, "%s\n", current.ptr);

        te_string_free(&current);
        line = (eol != NULL) ? eol + 1 : NULL;
    }

    te_string_free(&header);
    te_string_free(&name);

    return found;
}
