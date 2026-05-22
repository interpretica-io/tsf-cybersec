/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief objdump TAPI
 *
 * @defgroup tapi_objdump Static analysis with objdump (tapi_objdump)
 * @ingroup tapi_cybersec
 * @{
 *
 * Look inside a binary with @c objdump, from a test.
 *
 * @ref tapi_binscan answers how a binary was built by reading its ELF
 * structure; this answers what is actually in the code. The two do not
 * overlap: symbols and headers come from the ELF reader, which needs
 * nothing installed anywhere, and disassembly comes from here, which
 * needs binutils.
 *
 * What a test does with it:
 *
 * - **check that the shipped binary is the fixed one.** A patch that is
 *   in the source tree and not in the artifact is a class of bug that
 *   only the artifact can show.
 * - **find the unsafe call that survived review.** A reference to
 *   @c strcpy or @c system in a release binary is a lead, and the
 *   disassembly says which function it is in.
 * - **confirm a mitigation reached the code**, when the compiler flag
 *   alone does not prove it.
 *
 * @code
 * tapi_objdump_opt opt = tapi_objdump_default_opt;
 *
 * opt.path = "/usr/sbin/dutd";
 * CHECK_RC(tapi_objdump_check_banned(factory, &opt, NULL,
 *                                    TAPI_DEVTOOL_TIMEOUT_MS, &report));
 * @endcode
 *
 * @note @c objdump runs on the agent behind @p factory and reads a path
 *       on that agent. For a binary that lives on a device with no
 *       binutils - the usual case - copy it to an agent that has them
 *       with tapi_file_copy_ta() first; an agent on the engine host
 *       will do, and for a cross target it is the one place the cross
 *       binutils are.
 *
 * @note For a cross target, name the toolchain: the @c objdump of
 *       tapi_devtool_toolchain::cross_compile is used, because the host
 *       one cannot disassemble another architecture.
 */

#ifndef __TSF_TAPI_OBJDUMP_H__
#define __TSF_TAPI_OBJDUMP_H__

#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_devtool.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Functions whose presence in a release binary is worth a look: the
 * ones with no bound on what they write, the ones that hand a string to
 * a shell, and the ones that are simply not to be used.
 *
 * A @c NULL terminated array, meant to be passed to
 * tapi_objdump_check_banned() and to the Frida tracer, so that the
 * static and the dynamic answer are about the same list.
 */
extern const char *const tapi_objdump_default_banned[];

/** @c objdump invocation options. */
typedef struct tapi_objdump_opt {
    /** Toolchain to take the cross prefix from (@c NULL for the native one). */
    const tapi_devtool_toolchain *toolchain;
    /** @c objdump program; overrides the toolchain when not @c NULL. */
    const char *objdump;
    /** Path of the binary on the agent. Mandatory. */
    const char *path;

    /** Disassemble the executable sections (@c -d). */
    bool disassemble;
    /** Disassemble everything, data included (@c -D). */
    bool disassemble_all;
    /** Disassemble just this symbol (@c --disassemble=). */
    const char *symbol;
    /** Print the dynamic symbol table (@c -T). */
    bool dynamic_symbols;
    /** Print the symbol table (@c -t). */
    bool symbols;
    /** Print the relocation entries (@c -r). */
    bool relocs;
    /** Print the dynamic relocation entries (@c -R). */
    bool dynamic_relocs;
    /** Print the section headers (@c -h). */
    bool section_headers;
    /** Print the overall file header (@c -f). */
    bool file_headers;
    /** Demangle C++ names (@c -C). */
    bool demangle;
    /** Do not truncate lines (@c -w). */
    bool wide;
    /** Limit the output to one section (@c -j). */
    const char *section;

    /** Working directory on the agent (@c NULL to keep the default one). */
    const char *workdir;
} tapi_objdump_opt;

/** Default options: native toolchain, disassembly, demangled and wide. */
extern const tapi_objdump_opt tapi_objdump_default_opt;

/** @c objdump invocation handle. */
typedef struct tapi_objdump_app tapi_objdump_app;

/**
 * Create an @c objdump invocation.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Options.
 * @param[out] app          Handle.
 *
 * @return Status code.
 * @retval TE_EINVAL        tapi_objdump_opt::path is not set.
 */
extern te_errno tapi_objdump_create(tapi_job_factory_t *factory,
                                    const tapi_objdump_opt *opt,
                                    tapi_objdump_app **app);

/**
 * Start @c objdump. The output of a previous run is dropped.
 *
 * @param app           Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_objdump_start(tapi_objdump_app *app);

/**
 * Wait for @c objdump and capture its output.
 *
 * @param app           Handle.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_ESHCMD    @c objdump failed.
 */
extern te_errno tapi_objdump_wait(tapi_objdump_app *app, int timeout_ms);

/**
 * Send a signal to @c objdump.
 *
 * @param app           Handle.
 * @param signum        Signal number.
 *
 * @return Status code.
 */
extern te_errno tapi_objdump_kill(tapi_objdump_app *app, int signum);

/**
 * Stop @c objdump; it can be started over with tapi_objdump_start().
 *
 * @param app           Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_objdump_stop(tapi_objdump_app *app);

/**
 * Get what @c objdump printed and how it exited.
 *
 * @param[in]  app      Handle.
 * @param[out] output   Output description; the strings belong to @p app.
 */
extern void tapi_objdump_get_output(const tapi_objdump_app *app,
                                    tapi_devtool_output *output);

/**
 * Destroy a handle. It must not be used afterwards.
 *
 * @param app           Handle (may be @c NULL).
 *
 * @return Status code.
 */
extern te_errno tapi_objdump_destroy(tapi_objdump_app *app);

/**
 * Create, start and wait for an @c objdump invocation.
 *
 * The handle is returned even on failure, so that the test can report
 * what @c objdump said; destroy it with tapi_objdump_destroy().
 *
 * @param[in]  factory      Job factory.
 * @param[in]  opt          Options.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] app          Handle.
 *
 * @return Status code.
 */
extern te_errno tapi_objdump_do(tapi_job_factory_t *factory,
                                const tapi_objdump_opt *opt,
                                int timeout_ms,
                                tapi_objdump_app **app);

/**
 * Disassemble a binary and report every reference to a function that
 * should not be in it.
 *
 * The disassembly is walked keeping track of which function each line
 * belongs to, so a finding names the caller, which is what makes it
 * actionable. It reports a *reference*, not a proven call: a reference
 * inside a branch that never runs still shows up. Confirming that it
 * runs is what @ref tapi_frida is for.
 *
 * @param[in]     factory     Job factory.
 * @param[in]     opt         Options; @a disassemble is forced on.
 * @param[in]     banned      @c NULL terminated array of function names,
 *                            or @c NULL for
 *                            @ref tapi_objdump_default_banned.
 * @param[in]     timeout_ms  Timeout, ms.
 * @param[in,out] report      Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_objdump_check_banned(tapi_job_factory_t *factory,
                                          const tapi_objdump_opt *opt,
                                          const char *const *banned,
                                          int timeout_ms,
                                          tapi_cybersec_report *report);

/**
 * Find a symbol's disassembly in @c objdump output.
 *
 * @param[in]  text     Output of a disassembling run.
 * @param[in]  symbol   Function name.
 * @param[out] dest     String to append the function's lines to.
 *
 * @return @c true if the function was found.
 */
extern bool tapi_objdump_extract_function(const char *text,
                                          const char *symbol,
                                          te_string *dest);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_OBJDUMP_H__ */

/**@} <!-- END tapi_objdump --> */
