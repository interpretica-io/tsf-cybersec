/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Network exposure scanner
 *
 * The inside view reads the socket tables of the agent; the outside
 * view connects to ports over RPC sockets.
 */

#define TE_LGR_USER "TAPI NETEXPOSE"

#include "te_config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "logger_api.h"
#include "tapi_rpc_socket.h"
#include "tapi_rpc_unistd.h"
#include "te_alloc.h"
#include "te_sockaddr.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_kernel.h"
#include "tapi_netexpose.h"

const tapi_netexpose_opt tapi_netexpose_default_opt = {
    .ipv4             = true,
    .ipv6             = true,
    .tcp              = true,
    .udp              = true,
    .agent_big_endian = false,
};

/** One socket table file and what it holds. */
typedef struct netexpose_table {
    const char *path;
    int family;
    int proto;
} netexpose_table;

static const netexpose_table netexpose_tables[] = {
    { "/proc/net/tcp",  AF_INET,  IPPROTO_TCP },
    { "/proc/net/tcp6", AF_INET6, IPPROTO_TCP },
    { "/proc/net/udp",  AF_INET,  IPPROTO_UDP },
    { "/proc/net/udp6", AF_INET6, IPPROTO_UDP },
};

/**
 * Decode an address as /proc/net prints it.
 *
 * The kernel prints each 32-bit word of the address with @c %08X, so
 * the hex digits are in the byte order of the agent, not in network
 * order.
 */
static bool
netexpose_parse_addr(const char *hex, int family, bool big_endian, void *dst)
{
    size_t words = (family == AF_INET) ? 1 : 4;
    uint8_t *out = dst;
    size_t w;
    size_t i;

    if (strlen(hex) != words * 8)
        return false;

    for (w = 0; w < words; w++)
    {
        uint32_t value = 0;

        for (i = 0; i < 8; i++)
        {
            char c = hex[w * 8 + i];
            uint32_t digit;

            if (c >= '0' && c <= '9')
                digit = (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = (uint32_t)(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F')
                digit = (uint32_t)(c - 'A') + 10;
            else
                return false;

            value = (value << 4) | digit;
        }

        if (big_endian)
        {
            out[w * 4 + 0] = (uint8_t)(value >> 24);
            out[w * 4 + 1] = (uint8_t)(value >> 16);
            out[w * 4 + 2] = (uint8_t)(value >> 8);
            out[w * 4 + 3] = (uint8_t)value;
        }
        else
        {
            out[w * 4 + 0] = (uint8_t)value;
            out[w * 4 + 1] = (uint8_t)(value >> 8);
            out[w * 4 + 2] = (uint8_t)(value >> 16);
            out[w * 4 + 3] = (uint8_t)(value >> 24);
        }
    }

    return true;
}

/** Build a sockaddr from a decoded address and a port. */
static void
netexpose_make_sockaddr(int family, const uint8_t *raw, unsigned int port,
                        struct sockaddr_storage *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->ss_family = (sa_family_t)family;

    if (family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)dst;

        memcpy(&sin->sin_addr, raw, 4);
        sin->sin_port = htons((uint16_t)port);
    }
    else
    {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dst;

        memcpy(&sin6->sin6_addr, raw, 16);
        sin6->sin6_port = htons((uint16_t)port);
    }
}

/** Parse one entry of a socket table. */
static bool
netexpose_parse_line(const char *line, const netexpose_table *table,
                     bool big_endian, tapi_netexpose_socket *sock)
{
    char local_hex[33];
    char remote_hex[33];
    uint8_t local_raw[16];
    uint8_t remote_raw[16];
    unsigned int local_port;
    unsigned int remote_port;
    unsigned int state;
    unsigned int uid;
    unsigned long inode;

    if (sscanf(line,
               "%*u: %32[0-9A-Fa-f]:%X %32[0-9A-Fa-f]:%X %X %*X:%*X %*X:%*X "
               "%*X %u %*u %lu",
               local_hex, &local_port, remote_hex, &remote_port, &state,
               &uid, &inode) != 7)
        return false;

    if (!netexpose_parse_addr(local_hex, table->family, big_endian,
                              local_raw) ||
        !netexpose_parse_addr(remote_hex, table->family, big_endian,
                              remote_raw))
        return false;

    memset(sock, 0, sizeof(*sock));
    sock->family = table->family;
    sock->proto = table->proto;
    sock->state = state;
    sock->uid = uid;
    sock->inode = inode;
    netexpose_make_sockaddr(table->family, local_raw, local_port,
                            &sock->local);
    netexpose_make_sockaddr(table->family, remote_raw, remote_port,
                            &sock->remote);

    return true;
}

/* See description in tapi_netexpose.h */
te_errno
tapi_netexpose_sockets(tapi_job_factory_t *factory,
                       const tapi_netexpose_opt *opt, te_vec *sockets)
{
    size_t t;
    te_errno rc = 0;

    if (opt == NULL)
        opt = &tapi_netexpose_default_opt;

    *sockets = (te_vec)TE_VEC_INIT(tapi_netexpose_socket);

    for (t = 0; t < TE_ARRAY_LEN(netexpose_tables); t++)
    {
        const netexpose_table *table = &netexpose_tables[t];
        te_string content = TE_STRING_INIT;
        bool present = false;
        char *line;
        char *saveptr = NULL;
        bool first = true;

        if ((table->family == AF_INET && !opt->ipv4) ||
            (table->family == AF_INET6 && !opt->ipv6) ||
            (table->proto == IPPROTO_TCP && !opt->tcp) ||
            (table->proto == IPPROTO_UDP && !opt->udp))
            continue;

        /*
         * A kernel without IPv6 has no tcp6 or udp6, which is an answer
         * rather than a failure.
         */
        rc = tapi_kernel_read_optional(factory, &content, &present, "%s",
                                       table->path);
        if (rc != 0)
        {
            te_string_free(&content);
            goto out;
        }
        if (!present)
        {
            te_string_free(&content);
            continue;
        }

        for (line = strtok_r(content.ptr, "\n", &saveptr);
             line != NULL;
             line = strtok_r(NULL, "\n", &saveptr))
        {
            tapi_netexpose_socket sock;

            /* The first line is the column header. */
            if (first)
            {
                first = false;
                continue;
            }

            if (netexpose_parse_line(line, table, opt->agent_big_endian,
                                     &sock))
                TE_VEC_APPEND(sockets, sock);
            else
                WARN("Cannot parse a line of %s", table->path);
        }

        te_string_free(&content);
    }

out:
    if (rc != 0)
        tapi_netexpose_sockets_free(sockets);

    return rc;
}

/* See description in tapi_netexpose.h */
bool
tapi_netexpose_socket_is_listening(const tapi_netexpose_socket *sock)
{
    if (sock->proto == IPPROTO_TCP)
        return sock->state == TAPI_NETEXPOSE_TCP_LISTEN;

    /* A UDP server is a bound socket that has not been connected. */
    return te_sockaddr_get_port(CONST_SA(&sock->remote)) == 0;
}

/** Is the address one only this host can reach? */
static bool
netexpose_is_loopback(const struct sockaddr *addr)
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

/** Print an address and port the way a person reads it. */
static void
netexpose_addr2str(const struct sockaddr *addr, te_string *dest)
{
    char buf[INET6_ADDRSTRLEN] = "?";

    if (addr->sa_family == AF_INET)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        te_string_append(dest, "%s:%u", buf, ntohs(sin->sin_port));
    }
    else
    {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
        te_string_append(dest, "[%s]:%u", buf, ntohs(sin6->sin6_port));
    }
}

/* See description in tapi_netexpose.h */
void
tapi_netexpose_sockets_log(const te_vec *sockets, bool listening_only)
{
    const tapi_netexpose_socket *sock;

    RING("Socket table: %u entries", (unsigned int)te_vec_size(sockets));

    TE_VEC_FOREACH(sockets, sock)
    {
        te_string local = TE_STRING_INIT;
        te_string remote = TE_STRING_INIT;
        bool listening = tapi_netexpose_socket_is_listening(sock);

        if (listening_only && !listening)
            continue;

        netexpose_addr2str(CONST_SA(&sock->local), &local);
        netexpose_addr2str(CONST_SA(&sock->remote), &remote);

        RING("  %s %s%s%s uid %u",
             sock->proto == IPPROTO_TCP ? "tcp" : "udp",
             local.ptr,
             listening ? " listening" : " -> ",
             listening ? "" : remote.ptr,
             sock->uid);

        te_string_free(&local);
        te_string_free(&remote);
    }
}

/* See description in tapi_netexpose.h */
void
tapi_netexpose_sockets_free(te_vec *sockets)
{
    te_vec_free(sockets);
}

/* See description in tapi_netexpose.h */
te_errno
tapi_netexpose_check(tapi_job_factory_t *factory,
                     const tapi_netexpose_opt *opt,
                     const tapi_netexpose_allowed *allowed, size_t n_allowed,
                     tapi_cybersec_report *report)
{
    const tapi_netexpose_socket *sock;
    te_vec sockets;
    te_errno rc;

    rc = tapi_netexpose_sockets(factory, opt, &sockets);
    if (rc != 0)
        return rc;

    tapi_netexpose_sockets_log(&sockets, true);

    TE_VEC_FOREACH(&sockets, sock)
    {
        const tapi_netexpose_allowed *match = NULL;
        te_string subject = TE_STRING_INIT;
        te_string where = TE_STRING_INIT;
        uint16_t port;
        size_t i;

        if (!tapi_netexpose_socket_is_listening(sock))
            continue;

        port = ntohs(te_sockaddr_get_port(CONST_SA(&sock->local)));

        for (i = 0; i < n_allowed; i++)
        {
            if (allowed[i].proto == sock->proto && allowed[i].port == port)
            {
                match = &allowed[i];
                break;
            }
        }

        te_string_append(&subject, "%s/%u",
                         sock->proto == IPPROTO_TCP ? "tcp" : "udp", port);
        netexpose_addr2str(CONST_SA(&sock->local), &where);

        if (match == NULL)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.unexpected-listener", subject.ptr,
                                     "bound at %s by uid %u, and nothing "
                                     "says it should be", where.ptr,
                                     sock->uid);
        }
        else if (match->loopback_only &&
                 !netexpose_is_loopback(CONST_SA(&sock->local)))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.listens-beyond-loopback",
                                     subject.ptr,
                                     "bound at %s, but it is only allowed on "
                                     "a loopback address", where.ptr);
        }

        te_string_free(&subject);
        te_string_free(&where);
    }

    tapi_netexpose_sockets_free(&sockets);

    return 0;
}

/* See description in tapi_netexpose.h */
te_errno
tapi_netexpose_probe_port(rcf_rpc_server *pco, const struct sockaddr *addr,
                          uint16_t port, int timeout_ms,
                          tapi_netexpose_port_state *state)
{
    struct sockaddr_storage target;
    struct rpc_pollfd pfd;
    rpc_socket_domain domain;
    int fd;
    int ret;
    int error = 0;

    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
    {
        ERROR("Only IPv4 and IPv6 can be probed");
        return TE_RC(TE_TAPI, TE_EAFNOSUPPORT);
    }

    memset(&target, 0, sizeof(target));
    memcpy(&target, addr, te_sockaddr_get_size(addr));
    te_sockaddr_set_port(SA(&target), htons(port));

    domain = (addr->sa_family == AF_INET6) ? RPC_PF_INET6 : RPC_PF_INET;

    RPC_AWAIT_ERROR(pco);
    fd = rpc_socket(pco, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    if (fd < 0)
    {
        ERROR("Cannot create a socket to probe with: %r", RPC_ERRNO(pco));
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    RPC_AWAIT_ERROR(pco);
    if (rpc_fcntl(pco, fd, RPC_F_SETFL, RPC_O_NONBLOCK) < 0)
    {
        ERROR("Cannot make the probing socket non-blocking: %r",
              RPC_ERRNO(pco));
        RPC_AWAIT_ERROR(pco);
        rpc_close(pco, fd);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    RPC_AWAIT_ERROR(pco);
    ret = rpc_connect(pco, fd, SA(&target));
    if (ret == 0)
    {
        *state = TAPI_NETEXPOSE_PORT_OPEN;
        goto done;
    }

    if (RPC_ERRNO(pco) != RPC_EINPROGRESS)
    {
        *state = (RPC_ERRNO(pco) == RPC_ECONNREFUSED) ?
                     TAPI_NETEXPOSE_PORT_CLOSED :
                     TAPI_NETEXPOSE_PORT_FILTERED;
        goto done;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = RPC_POLLOUT;

    RPC_AWAIT_ERROR(pco);
    ret = rpc_poll(pco, &pfd, 1, timeout_ms);
    if (ret < 0)
    {
        ERROR("Cannot wait for the probing connection: %r", RPC_ERRNO(pco));
        RPC_AWAIT_ERROR(pco);
        rpc_close(pco, fd);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }
    if (ret == 0)
    {
        /* Nothing came back at all: a filter, or a host that is not there. */
        *state = TAPI_NETEXPOSE_PORT_FILTERED;
        goto done;
    }

    RPC_AWAIT_ERROR(pco);
    if (rpc_getsockopt(pco, fd, RPC_SO_ERROR, &error) < 0)
    {
        ERROR("Cannot read the result of the probing connection: %r",
              RPC_ERRNO(pco));
        RPC_AWAIT_ERROR(pco);
        rpc_close(pco, fd);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    if (error == 0)
        *state = TAPI_NETEXPOSE_PORT_OPEN;
    else if (error == (int)RPC_ECONNREFUSED)
        *state = TAPI_NETEXPOSE_PORT_CLOSED;
    else
        *state = TAPI_NETEXPOSE_PORT_FILTERED;

done:
    RPC_AWAIT_ERROR(pco);
    rpc_close(pco, fd);

    return 0;
}

/* See description in tapi_netexpose.h */
te_errno
tapi_netexpose_scan(rcf_rpc_server *pco, const struct sockaddr *addr,
                    uint16_t first, uint16_t last, int timeout_ms,
                    te_vec *open_ports)
{
    unsigned int port;
    te_errno rc = 0;

    *open_ports = (te_vec)TE_VEC_INIT(uint16_t);

    if (first > last)
    {
        ERROR("Port range %u..%u is empty", first, last);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    for (port = first; port <= last; port++)
    {
        tapi_netexpose_port_state state;

        rc = tapi_netexpose_probe_port(pco, addr, (uint16_t)port, timeout_ms,
                                       &state);
        if (rc != 0)
        {
            te_vec_free(open_ports);
            return rc;
        }

        if (state == TAPI_NETEXPOSE_PORT_OPEN)
        {
            uint16_t value = (uint16_t)port;

            TE_VEC_APPEND(open_ports, value);
        }
    }

    return 0;
}

/* See description in tapi_netexpose.h */
te_errno
tapi_netexpose_scan_check(rcf_rpc_server *pco, const struct sockaddr *addr,
                          uint16_t first, uint16_t last, int timeout_ms,
                          const uint16_t *allowed, size_t n_allowed,
                          tapi_cybersec_report *report)
{
    const uint16_t *port;
    te_vec open_ports;
    te_string where = TE_STRING_INIT;
    te_errno rc;

    rc = tapi_netexpose_scan(pco, addr, first, last, timeout_ms, &open_ports);
    if (rc != 0)
        return rc;

    netexpose_addr2str(addr, &where);
    RING("Reachable from %s: %u of ports %u..%u",
         RPC_NAME(pco), (unsigned int)te_vec_size(&open_ports), first, last);

    TE_VEC_FOREACH(&open_ports, port)
    {
        te_string subject = TE_STRING_INIT;
        bool expected = false;
        size_t i;

        for (i = 0; i < n_allowed; i++)
        {
            if (allowed[i] == *port)
            {
                expected = true;
                break;
            }
        }

        te_string_append(&subject, "tcp/%u", *port);

        if (expected)
        {
            RING("  tcp/%u is open, as expected", *port);
        }
        else
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "net.unexpected-reachable-port",
                                     subject.ptr,
                                     "answers a connection from %s and "
                                     "nothing says it should", RPC_NAME(pco));
        }

        te_string_free(&subject);
    }

    te_string_free(&where);
    te_vec_free(&open_ports);

    return 0;
}
