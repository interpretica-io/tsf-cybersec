/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Outgoing connection scanner
 *
 * Implementation of the outgoing connection scanner.
 */

#define TE_LGR_USER "TAPI EGRESS"

#include "te_config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "logger_api.h"
#include "te_sockaddr.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_egress.h"

/** Parse "address/length" into raw bytes and a prefix length. */
static bool
egress_parse_cidr(const char *cidr, int *family, uint8_t *raw,
                  unsigned int *prefix)
{
    const char *slash = strchr(cidr, '/');
    char addr[INET6_ADDRSTRLEN];
    size_t addr_len;
    unsigned int max_prefix;

    addr_len = (slash != NULL) ? (size_t)(slash - cidr) : strlen(cidr);
    if (addr_len == 0 || addr_len >= sizeof(addr))
        return false;

    memcpy(addr, cidr, addr_len);
    addr[addr_len] = '\0';

    if (inet_pton(AF_INET, addr, raw) == 1)
    {
        *family = AF_INET;
        max_prefix = 32;
    }
    else if (inet_pton(AF_INET6, addr, raw) == 1)
    {
        *family = AF_INET6;
        max_prefix = 128;
    }
    else
    {
        return false;
    }

    if (slash == NULL)
    {
        *prefix = max_prefix;
        return true;
    }

    if (te_strtoui(slash + 1, 10, prefix) != 0 || *prefix > max_prefix)
        return false;

    return true;
}

/** Do the first @p prefix bits of two addresses agree? */
static bool
egress_prefix_match(const uint8_t *a, const uint8_t *b, unsigned int prefix)
{
    unsigned int whole = prefix / 8;
    unsigned int rest = prefix % 8;

    if (whole != 0 && memcmp(a, b, whole) != 0)
        return false;

    if (rest != 0)
    {
        uint8_t mask = (uint8_t)(0xff << (8 - rest));

        if (((a[whole] ^ b[whole]) & mask) != 0)
            return false;
    }

    return true;
}

/** Get the raw address bytes of a sockaddr. */
static const uint8_t *
egress_raw_addr(const struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET)
        return (const uint8_t *)&((const struct sockaddr_in *)addr)->sin_addr;

    if (addr->sa_family == AF_INET6)
        return (const uint8_t *)
               &((const struct sockaddr_in6 *)addr)->sin6_addr;

    return NULL;
}

/** Is this an address the host only talks to itself on? */
static bool
egress_is_loopback(const struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

        return (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
    }

    if (addr->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }

    return false;
}

/** Is this an address that cannot be routed off the site? */
static bool
egress_is_private(const struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t host = ntohl(sin->sin_addr.s_addr);

        return (host >> 24) == 10 ||                     /* 10/8 */
               (host >> 20) == 0xac1 ||                  /* 172.16/12 */
               (host >> 16) == 0xc0a8 ||                 /* 192.168/16 */
               (host >> 16) == 0xa9fe;                   /* 169.254/16 */
    }

    if (addr->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

        return IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) ||
               IN6_IS_ADDR_SITELOCAL(&sin6->sin6_addr) ||
               (sin6->sin6_addr.s6_addr[0] & 0xfe) == 0xfc; /* fc00::/7 */
    }

    return false;
}

/* See description in tapi_egress.h */
bool
tapi_egress_policy_allows(const tapi_egress_policy *policy, int proto,
                          const struct sockaddr *addr)
{
    const uint8_t *raw = egress_raw_addr(addr);
    uint16_t port = ntohs(te_sockaddr_get_port(addr));
    size_t i;

    if (raw == NULL)
        return false;

    if (policy->allow_loopback && egress_is_loopback(addr))
        return true;

    if (policy->allow_private && egress_is_private(addr))
        return true;

    for (i = 0; i < policy->n_rules; i++)
    {
        const tapi_egress_rule *rule = &policy->rules[i];

        if (rule->proto != 0 && rule->proto != proto)
            continue;

        if (rule->port_min != 0 &&
            (port < rule->port_min || port > rule->port_max))
            continue;

        if (rule->cidr != NULL)
        {
            uint8_t prefix_raw[16];
            unsigned int prefix;
            int family;

            if (!egress_parse_cidr(rule->cidr, &family, prefix_raw, &prefix))
            {
                WARN("Egress rule %zu has an unusable prefix '%s'", i,
                     rule->cidr);
                continue;
            }

            if (family != addr->sa_family)
                continue;

            if (!egress_prefix_match(raw, prefix_raw, prefix))
                continue;
        }

        return true;
    }

    return false;
}

/* See description in tapi_egress.h */
te_errno
tapi_egress_snapshot(tapi_job_factory_t *factory,
                     const tapi_netexpose_opt *opt, te_vec *conns)
{
    const tapi_netexpose_socket *sock;
    te_vec sockets;
    te_errno rc;

    *conns = (te_vec)TE_VEC_INIT(tapi_netexpose_socket);

    rc = tapi_netexpose_sockets(factory, opt, &sockets);
    if (rc != 0)
    {
        te_vec_free(conns);
        return rc;
    }

    TE_VEC_FOREACH(&sockets, sock)
    {
        /* A peer port of zero means the socket was never connected. */
        if (te_sockaddr_get_port(CONST_SA(&sock->remote)) == 0)
            continue;

        if (tapi_netexpose_socket_is_listening(sock))
            continue;

        TE_VEC_APPEND(conns, *sock);
    }

    tapi_netexpose_sockets_free(&sockets);

    return 0;
}

/* See description in tapi_egress.h */
te_errno
tapi_egress_check(tapi_job_factory_t *factory, const tapi_netexpose_opt *opt,
                  const tapi_egress_policy *policy,
                  tapi_cybersec_report *report)
{
    const tapi_netexpose_socket *conn;
    te_vec conns;
    te_errno rc;

    rc = tapi_egress_snapshot(factory, opt, &conns);
    if (rc != 0)
        return rc;

    RING("Outgoing connections: %u", (unsigned int)te_vec_size(&conns));

    TE_VEC_FOREACH(&conns, conn)
    {
        char text[INET6_ADDRSTRLEN] = "?";
        te_string subject = TE_STRING_INIT;
        const void *raw;

        raw = egress_raw_addr(CONST_SA(&conn->remote));
        if (raw != NULL)
            inet_ntop(conn->family, raw, text, sizeof(text));

        te_string_append(&subject, "%s/%s:%u",
                         conn->proto == IPPROTO_TCP ? "tcp" : "udp", text,
                         ntohs(te_sockaddr_get_port(CONST_SA(&conn->remote))));

        if (tapi_egress_policy_allows(policy, conn->proto,
                                      CONST_SA(&conn->remote)))
        {
            RING("  %s: allowed", subject.ptr);
        }
        else
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.unexpected-egress", subject.ptr,
                                     "the agent has a connection there, and "
                                     "no rule allows it (socket owned by uid "
                                     "%u)", conn->uid);
        }

        te_string_free(&subject);
    }

    te_vec_free(&conns);

    return 0;
}
