/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Frida TAPI
 *
 * @defgroup tapi_frida Dynamic instrumentation with Frida (tapi_frida)
 * @ingroup tapi_cybersec
 * @{
 *
 * Watch what a running program actually does, and make it take the path
 * it will not take by itself.
 *
 * @ref tapi_objdump says a binary references @c strcpy somewhere.
 * This says it called it, with these arguments, from this function,
 * while the test was doing that. The difference is the difference
 * between a lead and a defect.
 *
 * It is the userspace twin of the kernel probes of tsf-kernel, and the
 * same rule applies: this is test equipment. It never ships with the
 * product, it runs on a lab machine, and it exists to make a defect
 * observable so that it can be closed.
 *
 * Three things a test does with it:
 *
 * - **observe**: which functions ran, which files were opened, which
 *   addresses were connected to - all with the call site;
 * - **provoke**: make the @a n th @c malloc fail, or @c open return
 *   @c EACCES, and check the error path that nobody ever exercises;
 * - **confirm**: turn a static finding into a real one, or dismiss it
 *   as unreachable.
 *
 * @code
 * tapi_frida_opt opt = tapi_frida_default_opt;
 * tapi_frida_app *app = NULL;
 * te_string script = TE_STRING_INIT;
 * te_string path = TE_STRING_INIT;
 *
 * tapi_frida_script_trace_calls(tapi_objdump_default_banned, &script);
 * CHECK_RC(tapi_frida_script_put(ta, script.ptr, &path));
 *
 * opt.target_name = "dutd";
 * opt.script_path = path.ptr;
 *
 * CHECK_RC(tapi_frida_create(factory, &opt, &app));
 * CHECK_RC(tapi_frida_start(app));
 * ... drive the device under test ...
 * CHECK_RC(tapi_frida_stop(app));
 * CHECK_RC(tapi_frida_check_banned_calls(app, &report));
 * CLEANUP_CHECK_RC(tapi_frida_destroy(app));
 * @endcode
 *
 * @note Frida injects itself into the target. It changes timing, it can
 *       crash the process, and attaching needs permission to
 *       @c ptrace - on a hardened kernel
 *       @c kernel.yama.ptrace_scope refuses it, which
 *       tapi_kernel_security_posture_get() will have recorded.
 *
 * @note The generated scripts are written for Linux and glibc or musl:
 *       they read @c sockaddr the way Linux lays it out and set
 *       @c errno through @c __errno_location.
 */

#ifndef __TSF_TAPI_FRIDA_H__
#define __TSF_TAPI_FRIDA_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"
#include "tapi_job_opt.h"

#include "tapi_cybersec.h"
#include "tapi_devtool.h"
#include "tapi_egress.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Prefix every generated script puts in front of an event line. */
#define TAPI_FRIDA_EVENT_PREFIX "TSF|"

/** Frida invocation options. */
typedef struct tapi_frida_opt {
    /** The @c frida program; @c NULL means @c frida. */
    const char *frida;
    /**
     * Remote device, as @c host:port, given to @c -H. @c NULL runs
     * against the machine the tool runs on. A DUT needs
     * @c frida-server listening there.
     */
    const char *device;

    /** Attach to a running process by name (@c -n). */
    const char *target_name;
    /**
     * Attach to a running process by pid (@c -p). Use
     * @c TAPI_JOB_OPT_OMIT_UINT, as @ref tapi_frida_default_opt does,
     * to attach by name or to spawn instead.
     */
    unsigned int target_pid;
    /** Spawn this program instead of attaching (@c -f). */
    const char *spawn;
    /** Number of arguments for @a spawn. */
    size_t n_spawn_args;
    /** Arguments for @a spawn. */
    const char **spawn_args;

    /** Script to load, a path on the agent (@c -l). Mandatory. */
    const char *script_path;
    /** Let a spawned program run at once (@c --no-pause). */
    bool no_pause;
    /** JavaScript runtime, @c "qjs" or @c "v8" (@c --runtime=). */
    const char *runtime;

    /** Working directory on the agent (@c NULL to keep the default one). */
    const char *workdir;
} tapi_frida_opt;

/** Default options: local device, attach, quiet, no pause. */
extern const tapi_frida_opt tapi_frida_default_opt;

/** Frida invocation handle. */
typedef struct tapi_frida_app tapi_frida_app;

/** One line a generated script printed. */
typedef struct tapi_frida_event {
    /** What happened: @c "call", @c "open", @c "connect", @c "fail". */
    char *kind;
    /** What it happened to: a function, a path, an address. */
    char *name;
    /** Whatever the script added, e.g. the call site. */
    char *detail;
} tapi_frida_event;

/**
 * Check that Frida is there before a test relies on it.
 *
 * @param factory       Job factory.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_ENOENT    Frida is not installed on the agent.
 */
extern te_errno tapi_frida_check_available(tapi_job_factory_t *factory,
                                           int timeout_ms);

/**
 * Put a script on the agent.
 *
 * @param[in]  ta       Agent name.
 * @param[in]  script   Script text.
 * @param[out] path     String to append the path of the script to;
 *                      remove it with tapi_file_ta_unlink_fmt() when the
 *                      test is done.
 *
 * @return Status code.
 */
extern te_errno tapi_frida_script_put(const char *ta, const char *script,
                                      te_string *path);

/**
 * Build a script that reports every call to any of @p functions,
 * with the place it was called from.
 *
 * @param[in]  functions    @c NULL terminated array of function names.
 * @param[out] script       String to append the script to.
 */
extern void tapi_frida_script_trace_calls(const char *const *functions,
                                          te_string *script);

/**
 * Build a script that makes one call to @p function fail.
 *
 * The return value of the @p nth call is replaced, and @c errno is set
 * if @p err is not zero. This is fault injection where the kernel's own
 * mechanisms cannot reach: the error path of a userspace program that
 * nothing else will ever make it take.
 *
 * @param[in]  function     Function to make fail, e.g. @c "malloc".
 * @param[in]  nth          Which call to fail, counting from one.
 * @param[in]  retval       Value to return instead, as an integer.
 * @param[in]  err          @c errno to set, or @c 0 to leave it alone.
 * @param[out] script       String to append the script to.
 */
extern void tapi_frida_script_fail_call(const char *function,
                                        unsigned int nth, long retval,
                                        int err, te_string *script);

/**
 * Build a script that reports every file the target opens.
 *
 * @param[out] script       String to append the script to.
 */
extern void tapi_frida_script_trace_open(te_string *script);

/**
 * Build a script that reports every address the target connects to.
 *
 * @param[out] script       String to append the script to.
 */
extern void tapi_frida_script_trace_connect(te_string *script);

/**
 * Create a Frida invocation.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Options.
 * @param[out] app          Handle.
 *
 * @return Status code.
 * @retval TE_EINVAL        No script, or no target.
 */
extern te_errno tapi_frida_create(tapi_job_factory_t *factory,
                                  const tapi_frida_opt *opt,
                                  tapi_frida_app **app);

/**
 * Start Frida. It keeps running until it is stopped.
 *
 * @param app           Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_frida_start(tapi_frida_app *app);

/**
 * Wait for Frida to finish on its own, which it does only when the
 * target exits.
 *
 * @param app           Handle.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_EINPROGRESS   It is still running.
 */
extern te_errno tapi_frida_wait(tapi_frida_app *app, int timeout_ms);

/**
 * Stop Frida and detach from the target.
 *
 * This is the normal end of a session: start it, drive the device, stop
 * it, then look at the events.
 *
 * @param app           Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_frida_stop(tapi_frida_app *app);

/**
 * Get what Frida printed and how it exited.
 *
 * @param[in]  app      Handle.
 * @param[out] output   Output description; the strings belong to @p app.
 */
extern void tapi_frida_get_output(const tapi_frida_app *app,
                                  tapi_devtool_output *output);

/**
 * Destroy a handle. It must not be used afterwards.
 *
 * @param app           Handle (may be @c NULL).
 *
 * @return Status code.
 */
extern te_errno tapi_frida_destroy(tapi_frida_app *app);

/**
 * Collect the events a generated script reported.
 *
 * @param[in]  app      Handle, after tapi_frida_stop().
 * @param[out] events   Vector of #tapi_frida_event, initialized by the
 *                      call; release it with tapi_frida_events_free().
 *
 * @return Status code.
 */
extern te_errno tapi_frida_events(const tapi_frida_app *app, te_vec *events);

/**
 * Release collected events.
 *
 * @param events        Vector filled by tapi_frida_events().
 */
extern void tapi_frida_events_free(te_vec *events);

/**
 * Report every call a tracing script saw.
 *
 * A call that ran is a stronger finding than a reference in the
 * disassembly, and it carries the place it ran from.
 *
 * @param[in]     app     Handle, after tapi_frida_stop().
 * @param[in,out] report  Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_frida_check_banned_calls(const tapi_frida_app *app,
                                              tapi_cybersec_report *report);

/**
 * Report every connection a tracing script saw that the policy does not
 * allow.
 *
 * This sees what the traced process does, which the socket table can
 * miss: a connection that is opened and closed between two snapshots
 * still shows up here.
 *
 * @param[in]     app     Handle, after tapi_frida_stop().
 * @param[in]     policy  Where the process is allowed to connect.
 * @param[in,out] report  Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_frida_check_egress(const tapi_frida_app *app,
                                        const tapi_egress_policy *policy,
                                        tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_FRIDA_H__ */

/**@} <!-- END tapi_frida --> */
