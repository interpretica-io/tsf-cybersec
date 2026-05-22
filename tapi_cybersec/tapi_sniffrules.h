/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Security rules over captured traffic
 *
 * @defgroup tapi_sniffrules Traffic security rules (tapi_sniffrules)
 * @ingroup tapi_cybersec
 * @{
 *
 * Ready-made checks over what goes across an interface, for the
 * mistakes that keep being made with the common protocols.
 *
 * TE already knows how to capture traffic - CSAPs, patterns, the
 * sniffer. What it does not carry is an opinion about what is wrong
 * with the traffic. That is what this is: a capture window with rules
 * attached, and findings on the other side.
 *
 * @code
 * tapi_sniffrules_opt opt = tapi_sniffrules_default_opt;
 * tapi_sniffrules_session *session = NULL;
 *
 * opt.egress = &policy;
 *
 * CHECK_RC(tapi_sniffrules_start(ta, "eth0", &opt, &session));
 * ... drive the device under test ...
 * CHECK_RC(tapi_sniffrules_stop(session, &report));
 * @endcode
 *
 * @note Findings are deduplicated by what they are about, so a rule
 *       that matches a thousand packets of one flow reports one
 *       finding, not a thousand.
 *
 * @note A rule that recognises credentials reports the flow and the
 *       fact. It never records the value it matched, because a test log
 *       is not a place to put one.
 *
 * @note This is a capture on an interface of a Test Agent that the
 *       suite configures. It is not a general-purpose interception
 *       tool, and it wants a lab network where every party is part of
 *       the engagement.
 */

#ifndef __TSF_TAPI_SNIFFRULES_H__
#define __TSF_TAPI_SNIFFRULES_H__

#include "te_defs.h"
#include "te_errno.h"

#include "tapi_cybersec.h"
#include "tapi_egress.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @name The rules, as a bit mask. */
/**@{*/
/**
 * Traffic on a port whose protocol carries everything in the clear:
 * telnet, FTP, HTTP, POP3, IMAP, LDAP, SNMP, TFTP, syslog, VNC, MQTT,
 * redis, memcached.
 */
#define TAPI_SNIFFRULE_CLEARTEXT_PROTO      (1u << 0)
/**
 * Credentials in the clear: HTTP basic authentication, and the login
 * commands of FTP, POP3 and IMAP. The finding names the flow, never the
 * credential.
 */
#define TAPI_SNIFFRULE_CLEARTEXT_CREDS      (1u << 1)
/**
 * A TLS server that agreed to something older than TLS 1.2, or an SSL
 * handshake of any version.
 */
#define TAPI_SNIFFRULE_WEAK_TLS             (1u << 2)
/** DNS that is neither DoT nor DoH, i.e. queries anyone can read. */
#define TAPI_SNIFFRULE_PLAINTEXT_DNS        (1u << 3)
/**
 * Protocols that announce the host to the whole segment: mDNS, LLMNR,
 * NetBIOS name service, SSDP.
 */
#define TAPI_SNIFFRULE_NAME_LEAK            (1u << 4)
/**
 * A connection started towards somewhere the egress policy does not
 * allow. Needs tapi_sniffrules_opt::egress.
 */
#define TAPI_SNIFFRULE_UNEXPECTED_EGRESS    (1u << 5)
/** Every rule above. */
#define TAPI_SNIFFRULE_ALL                  0x3fu
/**@}*/

/** What to watch for. */
typedef struct tapi_sniffrules_opt {
    /** Rules to apply, as a bit mask of @c TAPI_SNIFFRULE_*. */
    unsigned int rules;
    /**
     * Where the device is allowed to connect, for
     * @ref TAPI_SNIFFRULE_UNEXPECTED_EGRESS. It must outlive the
     * session.
     */
    const tapi_egress_policy *egress;
    /** Capture IPv4. */
    bool ipv4;
    /** Capture IPv6. */
    bool ipv6;
} tapi_sniffrules_opt;

/** Default: every rule except the egress one, both address families. */
extern const tapi_sniffrules_opt tapi_sniffrules_default_opt;

/** A capture window with rules attached. */
typedef struct tapi_sniffrules_session tapi_sniffrules_session;

/**
 * Start capturing on an interface of an agent.
 *
 * @param[in]  ta       Agent name.
 * @param[in]  ifname   Interface to capture on.
 * @param[in]  opt      What to watch for, or @c NULL for the defaults.
 * @param[out] session  The session; it is released by
 *                      tapi_sniffrules_stop().
 *
 * @return Status code.
 */
extern te_errno tapi_sniffrules_start(const char *ta, const char *ifname,
                                      const tapi_sniffrules_opt *opt,
                                      tapi_sniffrules_session **session);

/**
 * Stop capturing and judge what was captured.
 *
 * The session is released whether the call succeeds or not.
 *
 * @param[in]     session  Session started by tapi_sniffrules_start().
 * @param[in,out] report   Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_sniffrules_stop(tapi_sniffrules_session *session,
                                     tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SNIFFRULES_H__ */

/**@} <!-- END tapi_sniffrules --> */
