/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Security checks: findings and reports
 *
 * @defgroup tapi_cybersec Security checks (tapi_cybersec)
 * @{
 *
 * What the security scanners of this repository produce, and how a test
 * turns it into a result.
 *
 * - @ref tapi_binscan - how a binary on the agent was built: the
 *   hardening a compiler and linker were asked for, and what it linked;
 * - @ref tapi_netexpose - what the agent listens on and what of it is
 *   reachable from elsewhere, scanned over sockets rather than by
 *   driving @c nmap;
 * - @ref tapi_egress - what the agent talks to, against what it is
 *   allowed to talk to;
 * - @ref tapi_sniffrules - ready-made rules over captured traffic for
 *   the usual protocol mistakes.
 *
 * Every scanner appends to a #tapi_cybersec_report instead of failing
 * the test itself, for two reasons: one run should report everything it
 * found rather than the first thing, and the test decides what is worth
 * failing over. A gate looks like this:
 *
 * @code
 * tapi_cybersec_report report;
 * te_string verdict = TE_STRING_INIT;
 *
 * tapi_cybersec_report_init(&report);
 * CHECK_RC(tapi_binscan_check(ta, path, NULL, &report));
 * tapi_cybersec_report_log(&report);
 *
 * if (tapi_cybersec_report_verdict(&report, TAPI_CYBERSEC_SEV_HIGH,
 *                                  &verdict))
 *     TEST_VERDICT("%s", verdict.ptr);
 * @endcode
 *
 * @note A verdict built here names the check and its subject and
 *       nothing else - no counts, no addresses that change between
 *       runs - so that TRC can match it and a known issue stays a known
 *       issue. Keep it that way.
 */

#ifndef __TSF_TAPI_CYBERSEC_H__
#define __TSF_TAPI_CYBERSEC_H__

#include "te_compiler.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"

#ifdef __cplusplus
extern "C" {
#endif

/** How much a finding matters. */
typedef enum tapi_cybersec_severity {
    /** Worth recording, not worth acting on. */
    TAPI_CYBERSEC_SEV_INFO = 0,
    /** A weakness that needs something else to go wrong first. */
    TAPI_CYBERSEC_SEV_LOW,
    /** A weakness that makes an attack easier. */
    TAPI_CYBERSEC_SEV_MEDIUM,
    /** A missing defence, or exposure that should not be there. */
    TAPI_CYBERSEC_SEV_HIGH,
    /** Something is wrong right now. */
    TAPI_CYBERSEC_SEV_CRITICAL,
} tapi_cybersec_severity;

/** One thing a scanner found. */
typedef struct tapi_cybersec_finding {
    /** How much it matters. */
    tapi_cybersec_severity severity;
    /**
     * Stable identifier of the check, e.g. @c "binary.no-relro". It
     * never changes once it exists, because TRC matches on it.
     */
    char *check;
    /**
     * What the finding is about: a path, an address and port, a flow.
     * Part of the verdict, so it must not carry anything that differs
     * between runs.
     */
    char *subject;
    /** Free text for the log; not part of the verdict. */
    char *detail;
} tapi_cybersec_finding;

/** Everything one or more scanners found. */
typedef struct tapi_cybersec_report {
    /** Vector of #tapi_cybersec_finding, in the order they were found. */
    te_vec findings;
} tapi_cybersec_report;

/**
 * Prepare a report.
 *
 * @param report        Report.
 */
extern void tapi_cybersec_report_init(tapi_cybersec_report *report);

/**
 * Add a finding to a report.
 *
 * @param report        Report.
 * @param severity      How much it matters.
 * @param check         Stable check identifier.
 * @param subject       What the finding is about.
 * @param detail_fmt    Format string of the detail text.
 * @param ...           Format arguments.
 */
extern void tapi_cybersec_report_add(tapi_cybersec_report *report,
                                     tapi_cybersec_severity severity,
                                     const char *check,
                                     const char *subject,
                                     const char *detail_fmt, ...)
    TE_LIKE_PRINTF(5, 6);

/**
 * Count the findings of at least a given severity.
 *
 * @param report        Report.
 * @param min_severity  Lowest severity to count.
 *
 * @return Number of findings.
 */
extern unsigned int tapi_cybersec_report_count(
                                const tapi_cybersec_report *report,
                                tapi_cybersec_severity min_severity);

/**
 * Get the severity of the worst finding.
 *
 * @param report        Report.
 *
 * @return The worst severity, or @c TAPI_CYBERSEC_SEV_INFO for an empty
 *         report.
 */
extern tapi_cybersec_severity tapi_cybersec_report_worst(
                                const tapi_cybersec_report *report);

/**
 * Write a report into the log, one line per finding, worst first.
 *
 * @param report        Report.
 */
extern void tapi_cybersec_report_log(const tapi_cybersec_report *report);

/**
 * Build the verdict for a report.
 *
 * The text names the worst finding and nothing that varies between
 * runs, so it can go straight into @c TEST_VERDICT() and into
 * @c conf/trc.xml.
 *
 * @param[in]  report       Report.
 * @param[in]  min_severity Lowest severity worth failing over.
 * @param[out] dest         String to append the verdict to; untouched
 *                          when there is nothing to report.
 *
 * @return @c true if the report holds a finding of at least
 *         @p min_severity, i.e. the test should fail.
 */
extern bool tapi_cybersec_report_verdict(const tapi_cybersec_report *report,
                                         tapi_cybersec_severity min_severity,
                                         te_string *dest);

/**
 * Release a report.
 *
 * @param report        Report.
 */
extern void tapi_cybersec_report_free(tapi_cybersec_report *report);

/**
 * Spell out a severity.
 *
 * @param severity      Severity.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_cybersec_severity2str(
                                tapi_cybersec_severity severity);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_CYBERSEC_H__ */

/**@} <!-- END tapi_cybersec --> */
