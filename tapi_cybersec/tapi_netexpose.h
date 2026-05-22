/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Network exposure scanner
 *
 * @defgroup tapi_netexpose Network exposure (tapi_netexpose)
 * @ingroup tapi_cybersec
 * @{
 *
 * What an agent listens on, and what of it another host can actually
 * reach.
 *
 * Two views, and a test wants both:
 *
 * - **from the inside**, by reading the socket tables of the agent.
 *   This is exact - every listener, with the address it is bound to and
 *   the user that owns it - and it costs one command;
 * - **from the outside**, by connecting to ports from another agent.
 *   This is what an attacker sees, filtering and firewalls included.
 *   A port that the inside view shows as bound and the outside view
 *   cannot reach is a firewall doing its job; the other way round is a
 *   surprise worth a finding.
 *
 * The outside view is a TCP connect scan built on @ref tapi_rpc
 * sockets: no @c nmap, nothing installed on either side, and every
 * connection comes from a Test Agent that the suite already owns.
 *
 * @code
 * static const tapi_netexpose_allowed allowed[] = {
 *     { IPPROTO_TCP, 22,   false },
 *     { IPPROTO_TCP, 8080, true  },   // management, loopback only
 * };
 *
 * CHECK_RC(tapi_netexpose_check(factory, NULL, allowed,
 *                               TE_ARRAY_LEN(allowed), &report));
 * @endcode
 *
 * @note Scan only what the suite's own configuration describes. These
 *       functions take the address of a DUT from the test; pointing
 *       them at anything else is out of scope of the engagement the
 *       suite belongs to.
 */

#ifndef __TSF_TAPI_NETEXPOSE_H__
#define __TSF_TAPI_NETEXPOSE_H__

#include <netinet/in.h>
#include <sys/socket.h>

#include "rcf_rpc.h"
#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** State of a TCP socket in the kernel's socket table. */
#define TAPI_NETEXPOSE_TCP_ESTABLISHED  1
/** A TCP socket that is waiting for connections. */
#define TAPI_NETEXPOSE_TCP_LISTEN       10

/** One entry of the socket table of an agent. */
typedef struct tapi_netexpose_socket {
    /** @c AF_INET or @c AF_INET6. */
    int family;
    /** @c IPPROTO_TCP or @c IPPROTO_UDP. */
    int proto;
    /** Address and port the socket is bound to. */
    struct sockaddr_storage local;
    /** Address and port of the peer; all zeroes when there is none. */
    struct sockaddr_storage remote;
    /** State as the kernel numbers it; see @c TAPI_NETEXPOSE_TCP_*. */
    unsigned int state;
    /** Owner of the socket. */
    unsigned int uid;
    /** Inode, which is what ties a socket to a process. */
    unsigned long inode;
} tapi_netexpose_socket;

/** What to read from the socket tables. */
typedef struct tapi_netexpose_opt {
    /** Read the IPv4 tables. */
    bool ipv4;
    /** Read the IPv6 tables. */
    bool ipv6;
    /** Read the TCP tables. */
    bool tcp;
    /** Read the UDP tables. */
    bool udp;
    /**
     * The agent is big-endian.
     *
     * The kernel prints addresses in @c /proc/net as native words, so
     * reading them back needs to know the byte order of the agent. It
     * is not guessed: a guess that is right nearly always is worse than
     * a switch, because the rare wrong answer looks like a real
     * finding.
     */
    bool agent_big_endian;
} tapi_netexpose_opt;

/** Default: both families, both protocols, little-endian agent. */
extern const tapi_netexpose_opt tapi_netexpose_default_opt;

/**
 * Read the socket tables of an agent.
 *
 * @param[in]  factory  Job factory.
 * @param[in]  opt      What to read, or @c NULL for the defaults.
 * @param[out] sockets  Vector of #tapi_netexpose_socket, initialized by
 *                      the call; release it with
 *                      tapi_netexpose_sockets_free().
 *
 * @return Status code.
 */
extern te_errno tapi_netexpose_sockets(tapi_job_factory_t *factory,
                                       const tapi_netexpose_opt *opt,
                                       te_vec *sockets);

/**
 * Check whether a socket is waiting for connections.
 *
 * For TCP it is the @c LISTEN state; for UDP it is a socket that is
 * bound and has no peer, which is what a UDP server looks like.
 *
 * @param sock          Socket table entry.
 *
 * @return @c true if the socket accepts traffic from outside.
 */
extern bool tapi_netexpose_socket_is_listening(
                                const tapi_netexpose_socket *sock);

/**
 * Write a socket table into the log.
 *
 * @param sockets       Vector filled by tapi_netexpose_sockets().
 * @param listening_only Log only the sockets that accept traffic.
 */
extern void tapi_netexpose_sockets_log(const te_vec *sockets,
                                       bool listening_only);

/**
 * Release a socket table.
 *
 * @param sockets       Vector filled by tapi_netexpose_sockets().
 */
extern void tapi_netexpose_sockets_free(te_vec *sockets);

/** A listener the agent is allowed to have. */
typedef struct tapi_netexpose_allowed {
    /** @c IPPROTO_TCP or @c IPPROTO_UDP. */
    int proto;
    /** Port, in host byte order. */
    uint16_t port;
    /**
     * The service may only be bound to a loopback address. A management
     * interface that turns up on @c 0.0.0.0 is the finding this exists
     * for.
     */
    bool loopback_only;
} tapi_netexpose_allowed;

/**
 * Check what an agent listens on against what it is allowed to listen
 * on.
 *
 * @param[in]     factory     Job factory.
 * @param[in]     opt         What to read, or @c NULL for the defaults.
 * @param[in]     allowed     Listeners that are expected.
 * @param[in]     n_allowed   Number of @p allowed entries.
 * @param[in,out] report      Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_netexpose_check(tapi_job_factory_t *factory,
                                     const tapi_netexpose_opt *opt,
                                     const tapi_netexpose_allowed *allowed,
                                     size_t n_allowed,
                                     tapi_cybersec_report *report);

/** What a connection attempt to a port found. */
typedef enum tapi_netexpose_port_state {
    /** Nothing answered before the timeout: filtered, or dropped. */
    TAPI_NETEXPOSE_PORT_FILTERED = 0,
    /** The connection was refused: reachable, but nothing listens. */
    TAPI_NETEXPOSE_PORT_CLOSED,
    /** The connection was accepted. */
    TAPI_NETEXPOSE_PORT_OPEN,
} tapi_netexpose_port_state;

/**
 * Try to connect to one port of a host, from an agent.
 *
 * @param[in]  pco          RPC server the connection is made from.
 * @param[in]  addr         Address of the host; its port is ignored.
 * @param[in]  port         Port, in host byte order.
 * @param[in]  timeout_ms   How long to wait for an answer.
 * @param[out] state        What was found.
 *
 * @return Status code.
 */
extern te_errno tapi_netexpose_probe_port(rcf_rpc_server *pco,
                                          const struct sockaddr *addr,
                                          uint16_t port, int timeout_ms,
                                          tapi_netexpose_port_state *state);

/**
 * Try every port of a range, one at a time.
 *
 * @param[in]  pco          RPC server the connections are made from.
 * @param[in]  addr         Address of the host; its port is ignored.
 * @param[in]  first        First port of the range, in host byte order.
 * @param[in]  last         Last port of the range, in host byte order.
 * @param[in]  timeout_ms   How long to wait for each answer.
 * @param[out] open_ports   Vector of @c uint16_t, initialized by the
 *                          call; release it with te_vec_free().
 *
 * @return Status code.
 */
extern te_errno tapi_netexpose_scan(rcf_rpc_server *pco,
                                    const struct sockaddr *addr,
                                    uint16_t first, uint16_t last,
                                    int timeout_ms, te_vec *open_ports);

/**
 * Scan a range and report every port that answers and is not expected
 * to.
 *
 * @param[in]     pco         RPC server the connections are made from.
 * @param[in]     addr        Address of the host; its port is ignored.
 * @param[in]     first       First port of the range.
 * @param[in]     last        Last port of the range.
 * @param[in]     timeout_ms  How long to wait for each answer.
 * @param[in]     allowed     Ports that are expected to answer.
 * @param[in]     n_allowed   Number of @p allowed entries.
 * @param[in,out] report      Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_netexpose_scan_check(rcf_rpc_server *pco,
                                          const struct sockaddr *addr,
                                          uint16_t first, uint16_t last,
                                          int timeout_ms,
                                          const uint16_t *allowed,
                                          size_t n_allowed,
                                          tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_NETEXPOSE_H__ */

/**@} <!-- END tapi_netexpose --> */
