/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Security checks: findings and reports
 *
 * Implementation of the finding and report model.
 */

#define TE_LGR_USER "TAPI CYBERSEC"

#include "te_config.h"

#include <stdarg.h>
#include <stdlib.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_cybersec.h"

/* See description in tapi_cybersec.h */
void
tapi_cybersec_report_init(tapi_cybersec_report *report)
{
    report->findings = (te_vec)TE_VEC_INIT(tapi_cybersec_finding);
}

/* See description in tapi_cybersec.h */
void
tapi_cybersec_report_add(tapi_cybersec_report *report,
                         tapi_cybersec_severity severity, const char *check,
                         const char *subject, const char *detail_fmt, ...)
{
    tapi_cybersec_finding finding;
    te_string detail = TE_STRING_INIT;
    va_list ap;

    va_start(ap, detail_fmt);
    te_string_append_va(&detail, detail_fmt, ap);
    va_end(ap);

    finding.severity = severity;
    finding.check = TE_STRDUP(check);
    finding.subject = TE_STRDUP(subject != NULL ? subject : "");
    finding.detail = detail.ptr != NULL ? detail.ptr : TE_STRDUP("");

    TE_VEC_APPEND(&report->findings, finding);
}

/* See description in tapi_cybersec.h */
unsigned int
tapi_cybersec_report_count(const tapi_cybersec_report *report,
                           tapi_cybersec_severity min_severity)
{
    const tapi_cybersec_finding *finding;
    unsigned int count = 0;

    TE_VEC_FOREACH(&report->findings, finding)
    {
        if (finding->severity >= min_severity)
            count++;
    }

    return count;
}

/* See description in tapi_cybersec.h */
tapi_cybersec_severity
tapi_cybersec_report_worst(const tapi_cybersec_report *report)
{
    const tapi_cybersec_finding *finding;
    tapi_cybersec_severity worst = TAPI_CYBERSEC_SEV_INFO;

    TE_VEC_FOREACH(&report->findings, finding)
    {
        if (finding->severity > worst)
            worst = finding->severity;
    }

    return worst;
}

/** Find the first finding of exactly @p severity. */
static const tapi_cybersec_finding *
find_by_severity(const tapi_cybersec_report *report,
                 tapi_cybersec_severity severity)
{
    const tapi_cybersec_finding *finding;

    TE_VEC_FOREACH(&report->findings, finding)
    {
        if (finding->severity == severity)
            return finding;
    }

    return NULL;
}

/* See description in tapi_cybersec.h */
void
tapi_cybersec_report_log(const tapi_cybersec_report *report)
{
    const tapi_cybersec_finding *finding;
    tapi_cybersec_severity severity;

    if (te_vec_size(&report->findings) == 0)
    {
        RING("Security report: nothing found");
        return;
    }

    RING("Security report: %u findings",
         (unsigned int)te_vec_size(&report->findings));

    /*
     * Worst first: a log a person reads top down should start with what
     * matters. The vector keeps the order things were found in, so the
     * severities are walked instead of the findings.
     */
    severity = TAPI_CYBERSEC_SEV_CRITICAL;
    while (true)
    {
        TE_VEC_FOREACH(&report->findings, finding)
        {
            if (finding->severity != severity)
                continue;

            RING("  [%s] %s: %s%s%s",
                 tapi_cybersec_severity2str(finding->severity),
                 finding->check, finding->subject,
                 finding->detail[0] != '\0' ? " - " : "", finding->detail);
        }

        if (severity == TAPI_CYBERSEC_SEV_INFO)
            break;
        severity--;
    }
}

/* See description in tapi_cybersec.h */
bool
tapi_cybersec_report_verdict(const tapi_cybersec_report *report,
                             tapi_cybersec_severity min_severity,
                             te_string *dest)
{
    const tapi_cybersec_finding *worst_finding;
    tapi_cybersec_severity worst;

    worst = tapi_cybersec_report_worst(report);
    if (te_vec_size(&report->findings) == 0 || worst < min_severity)
        return false;

    worst_finding = find_by_severity(report, worst);
    if (worst_finding == NULL)
        return false;

    /*
     * Deliberately free of counts and of anything else that differs
     * between runs: this text is what TRC matches a known issue on.
     */
    te_string_append(dest, "security check %s failed for %s",
                     worst_finding->check, worst_finding->subject);

    return true;
}

/* See description in tapi_cybersec.h */
void
tapi_cybersec_report_free(tapi_cybersec_report *report)
{
    tapi_cybersec_finding *finding;

    TE_VEC_FOREACH(&report->findings, finding)
    {
        free(finding->check);
        free(finding->subject);
        free(finding->detail);
    }

    te_vec_free(&report->findings);
}

/* See description in tapi_cybersec.h */
const char *
tapi_cybersec_severity2str(tapi_cybersec_severity severity)
{
    switch (severity)
    {
        case TAPI_CYBERSEC_SEV_LOW:
            return "LOW";
        case TAPI_CYBERSEC_SEV_MEDIUM:
            return "MEDIUM";
        case TAPI_CYBERSEC_SEV_HIGH:
            return "HIGH";
        case TAPI_CYBERSEC_SEV_CRITICAL:
            return "CRITICAL";
        default:
            return "INFO";
    }
}
