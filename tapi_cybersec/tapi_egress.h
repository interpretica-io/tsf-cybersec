/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Outgoing connection scanner
 *
 * @defgroup tapi_egress Outgoing connections (tapi_egress)
 * @ingroup tapi_cybersec
 * @{
 *
 * What an agent talks to, against what it is allowed to talk to.
 *
 * A device that reaches out to somewhere nobody expected is one of the
 * few signals that is both cheap to collect and hard to argue with: a
 * telemetry endpoint nobody declared, an update server contacted over
 * plain HTTP, a DNS resolver that is not the one configured, a
 * connection that only appears after a particular feature is switched
 * on.
 *
 * The socket table is the precise view and it is what this reads. It
 * sees the connections the agent's own network stack has; traffic from
 * another namespace, or from the kernel itself, shows up on the wire
 * instead - @ref tapi_sniffrules carries the same policy for that.
 *
 * @code
 * static const tapi_egress_rule rules[] = {
 *     { IPPROTO_UDP, "10.0.0.53/32", 53,  53  },   // the resolver
 *     { IPPROTO_TCP, "10.0.0.0/8",   443, 443 },   // the update service
 * };
 * static const tapi_egress_policy policy = {
 *     .n_rules = TE_ARRAY_LEN(rules), .rules = rules,
 *     .allow_loopback = true,
 * };
 *
 * CHECK_RC(tapi_egress_check(factory, NULL, &policy, &report));
 * @endcode
 */

#ifndef __TSF_TAPI_EGRESS_H__
#define __TSF_TAPI_EGRESS_H__

#include <netinet/in.h>
#include <sys/socket.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_netexpose.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Somewhere the agent is allowed to connect to. */
typedef struct tapi_egress_rule {
    /** @c IPPROTO_TCP, @c IPPROTO_UDP, or @c 0 for either. */
    int proto;
    /**
     * Destination prefix, e.g. @c "10.0.0.0/8" or @c "2001:db8::/32".
     * @c NULL matches any address.
     */
    const char *cidr;
    /** Lowest destination port, or @c 0 for any. */
    uint16_t port_min;
    /** Highest destination port; ignored when @a port_min is @c 0. */
    uint16_t port_max;
} tapi_egress_rule;

/** Where the agent is allowed to talk. */
typedef struct tapi_egress_policy {
    /** Number of rules. */
    size_t n_rules;
    /** Rules; a connection matching any of them is allowed. */
    const tapi_egress_rule *rules;
    /** Connections to a loopback address are not egress at all. */
    bool allow_loopback;
    /**
     * Connections to a private or link-local address are allowed
     * without a rule. Useful on a lab network, misleading on a device
     * whose whole job is to stay inside one network.
     */
    bool allow_private;
} tapi_egress_policy;

/**
 * Take the outgoing connections an agent currently has.
 *
 * The entries are #tapi_netexpose_socket, the same record the socket
 * table is read into; only the ones with a peer are kept.
 *
 * @param[in]  factory  Job factory.
 * @param[in]  opt      What to read, or @c NULL for the defaults.
 * @param[out] conns    Vector of #tapi_netexpose_socket, initialized by
 *                      the call; release it with te_vec_free().
 *
 * @return Status code.
 */
extern te_errno tapi_egress_snapshot(tapi_job_factory_t *factory,
                                     const tapi_netexpose_opt *opt,
                                     te_vec *conns);

/**
 * Check one destination against a policy.
 *
 * @param policy        Policy.
 * @param proto         @c IPPROTO_TCP or @c IPPROTO_UDP.
 * @param addr          Destination address and port.
 *
 * @return @c true if the policy allows it.
 */
extern bool tapi_egress_policy_allows(const tapi_egress_policy *policy,
                                      int proto,
                                      const struct sockaddr *addr);

/**
 * Check what an agent is talking to against what it is allowed to talk
 * to.
 *
 * @param[in]     factory  Job factory.
 * @param[in]     opt      What to read, or @c NULL for the defaults.
 * @param[in]     policy   Policy.
 * @param[in,out] report   Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_egress_check(tapi_job_factory_t *factory,
                                  const tapi_netexpose_opt *opt,
                                  const tapi_egress_policy *policy,
                                  tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_EGRESS_H__ */

/**@} <!-- END tapi_egress --> */
