/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Binary hardening scanner
 *
 * @defgroup tapi_binscan Binary hardening (tapi_binscan)
 * @ingroup tapi_cybersec
 * @{
 *
 * What a binary on the agent was built with: the defences a compiler
 * and a linker were asked for, and what it carries.
 *
 * The binary is fetched to the engine and its ELF structure is read
 * there. Nothing is run, nothing is needed on the agent - no
 * @c readelf, no @c objdump, no @c checksec - and the binary does not
 * have to be for the same architecture or endianness as the engine,
 * which is the usual case for an embedded DUT.
 *
 * @code
 * tapi_cybersec_report report;
 *
 * tapi_cybersec_report_init(&report);
 * CHECK_RC(tapi_binscan_check(ta, "/usr/sbin/dutd", NULL, &report));
 * tapi_cybersec_report_log(&report);
 * @endcode
 *
 * @note This reads how the binary was built. It does not look for known
 *       vulnerabilities in it: that is a question about versions and a
 *       vulnerability database, not about the file.
 *
 * @note File permissions - setuid, setgid, world-writable - are a
 *       property of the filesystem rather than of the ELF, and are not
 *       covered here.
 */

#ifndef __TSF_TAPI_BINSCAN_H__
#define __TSF_TAPI_BINSCAN_H__

#include "te_defs.h"
#include "te_errno.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** How much of the relocation table is made read-only after startup. */
typedef enum tapi_binscan_relro {
    /** None of it. */
    TAPI_BINSCAN_RELRO_NONE = 0,
    /** There is a @c PT_GNU_RELRO segment, but the GOT stays writable. */
    TAPI_BINSCAN_RELRO_PARTIAL,
    /** Relocations are resolved at startup and the GOT is read-only. */
    TAPI_BINSCAN_RELRO_FULL,
} tapi_binscan_relro;

/** What kind of ELF object a file is. */
typedef enum tapi_binscan_kind {
    /** Not an ELF file at all. */
    TAPI_BINSCAN_KIND_OTHER = 0,
    /** A position-dependent executable. */
    TAPI_BINSCAN_KIND_EXEC,
    /** A position-independent executable: @c ET_DYN with an interpreter. */
    TAPI_BINSCAN_KIND_PIE,
    /** A shared library. */
    TAPI_BINSCAN_KIND_SHARED,
    /** A relocatable object or a core file. */
    TAPI_BINSCAN_KIND_RELOC,
} tapi_binscan_kind;

/** How a binary was built. */
typedef struct tapi_binscan_info {
    /** @c true if the file is an ELF object at all. */
    bool elf;
    /** @c 32 or @c 64. */
    unsigned int elf_class;
    /** @c true for little-endian. */
    bool little_endian;
    /** @c e_machine of the ELF header. */
    unsigned int machine;
    /** What kind of object it is. */
    tapi_binscan_kind kind;

    /** The stack is not executable. */
    bool nx;
    /** There is no @c PT_GNU_STACK segment, so the stack policy is the default. */
    bool nx_unknown;
    /** How much read-only relocation it has. */
    tapi_binscan_relro relro;
    /** It was built with stack protection. */
    bool canary;
    /** It was built with @c _FORTIFY_SOURCE. */
    bool fortify;
    /** It has no symbol table, so @a canary and @a fortify are guesses
     *  made from the dynamic symbols only. */
    bool stripped;
    /** It is statically linked: no interpreter and no dynamic section. */
    bool static_linked;
    /** It has text relocations, so code pages must be writable. */
    bool textrel;
    /** It has a segment that is both writable and executable. */
    bool wx_segment;

    /** @c DT_RPATH, or @c NULL. */
    char *rpath;
    /** @c DT_RUNPATH, or @c NULL. */
    char *runpath;
    /** Program interpreter, or @c NULL. */
    char *interp;
    /** Number of @c DT_NEEDED entries. */
    size_t n_needed;
    /** Shared libraries the binary needs. */
    char **needed;
} tapi_binscan_info;

/**
 * Read how a binary on the agent was built.
 *
 * @param[in]  ta       Agent name.
 * @param[in]  path     Path of the binary on the agent.
 * @param[out] info     What was found; release it with
 *                      tapi_binscan_info_free().
 *
 * @return Status code.
 * @retval TE_EBADMSG   The file is not an ELF object, or it is damaged.
 */
extern te_errno tapi_binscan_inspect(const char *ta, const char *path,
                                     tapi_binscan_info *info);

/**
 * Write what was found into the log.
 *
 * @param info          Result of tapi_binscan_inspect().
 * @param path          Path to name in the log.
 */
extern void tapi_binscan_info_log(const tapi_binscan_info *info,
                                  const char *path);

/**
 * Release what tapi_binscan_inspect() filled in.
 *
 * @param info          Result of tapi_binscan_inspect().
 */
extern void tapi_binscan_info_free(tapi_binscan_info *info);

/** What a binary is required to have. */
typedef struct tapi_binscan_policy {
    /** An executable must be position independent. */
    bool require_pie;
    /** The stack must be non-executable. */
    bool require_nx;
    /** Relocations must be fully read-only after startup. */
    bool require_full_relro;
    /** Partial RELRO is worth a finding of its own. */
    bool report_partial_relro;
    /** It must be built with stack protection. */
    bool require_canary;
    /** It must be built with @c _FORTIFY_SOURCE. */
    bool require_fortify;
    /** @c DT_RPATH is a finding. */
    bool forbid_rpath;
    /** @c DT_RUNPATH is a finding. */
    bool forbid_runpath;
    /** Text relocations are a finding. */
    bool forbid_textrel;
    /** A writable executable segment is a finding. */
    bool forbid_wx;
} tapi_binscan_policy;

/**
 * The default policy: everything above, except that @c DT_RUNPATH is
 * only reported and @c _FORTIFY_SOURCE is not required, because a
 * binary can legitimately have neither.
 */
extern const tapi_binscan_policy tapi_binscan_default_policy;

/**
 * Check a binary on the agent against a policy.
 *
 * @param[in]     ta        Agent name.
 * @param[in]     path      Path of the binary on the agent.
 * @param[in]     policy    Policy, or @c NULL for
 *                          @ref tapi_binscan_default_policy.
 * @param[in,out] report    Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_binscan_check(const char *ta, const char *path,
                                   const tapi_binscan_policy *policy,
                                   tapi_cybersec_report *report);

/**
 * Spell out a RELRO state.
 *
 * @param relro         RELRO state.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_binscan_relro2str(tapi_binscan_relro relro);

/**
 * Spell out an object kind.
 *
 * @param kind          Object kind.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_binscan_kind2str(tapi_binscan_kind kind);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_BINSCAN_H__ */

/**@} <!-- END tapi_binscan --> */
