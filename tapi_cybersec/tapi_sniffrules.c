/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Security rules over captured traffic
 *
 * One CSAP per address family and transport protocol, an accept-all
 * pattern, and the rules applied to every packet when the window
 * closes.
 */

#define TE_LGR_USER "TAPI SNIFFRULES"

#include "te_config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>

#include "asn_usr.h"
#include "logger_api.h"
#include "ndn.h"
#include "rcf_api.h"
#include "tad_common.h"
#include "tapi_ip_common.h"
#include "tapi_tad.h"
#include "te_alloc.h"
#include "te_kvpair.h"
#include "te_str.h"
#include "te_string.h"

#include "tapi_sniffrules.h"

/** Largest payload prefix the rules look at, bytes. */
#define SR_PAYLOAD_MAX  2048

/** How long to let a stop() drain a CSAP, ms. */
#define SR_STOP_TIMEOUT_MS  5000

const tapi_sniffrules_opt tapi_sniffrules_default_opt = {
    .rules = TAPI_SNIFFRULE_CLEARTEXT_PROTO | TAPI_SNIFFRULE_CLEARTEXT_CREDS |
             TAPI_SNIFFRULE_WEAK_TLS | TAPI_SNIFFRULE_PLAINTEXT_DNS |
             TAPI_SNIFFRULE_NAME_LEAK,
    .egress = NULL,
    .ipv4 = true,
    .ipv6 = true,
};

/** One capture channel. */
typedef struct sr_channel {
    csap_handle_t csap;
    int af;
    int proto;
} sr_channel;

struct tapi_sniffrules_session {
    char *ta;
    int sid;
    tapi_sniffrules_opt opt;
    sr_channel channels[4];
    size_t n_channels;

    /* Used while the packets are being walked. */
    tapi_cybersec_report *report;
    te_kvpair_h seen;
    unsigned int packets;
};

/** A protocol that carries everything in the clear. */
typedef struct sr_cleartext {
    int proto;
    uint16_t port;
    const char *name;
    bool carries_credentials;
} sr_cleartext;

static const sr_cleartext sr_cleartext_ports[] = {
    { IPPROTO_TCP,   21, "FTP",              true  },
    { IPPROTO_TCP,   23, "telnet",           true  },
    { IPPROTO_UDP,   69, "TFTP",             false },
    { IPPROTO_TCP,   80, "HTTP",             false },
    { IPPROTO_TCP,  110, "POP3",             true  },
    { IPPROTO_TCP,  143, "IMAP",             true  },
    { IPPROTO_UDP,  161, "SNMP",             true  },
    { IPPROTO_TCP,  389, "LDAP",             true  },
    { IPPROTO_TCP,  512, "rexec",            true  },
    { IPPROTO_TCP,  513, "rlogin",           true  },
    { IPPROTO_TCP,  514, "rsh",              true  },
    { IPPROTO_UDP,  514, "syslog",           false },
    { IPPROTO_TCP, 1883, "MQTT",             true  },
    { IPPROTO_TCP, 5900, "VNC",              true  },
    { IPPROTO_TCP, 6379, "redis",            true  },
    { IPPROTO_TCP,11211, "memcached",        false },
};

/** A protocol that tells the whole segment who this host is. */
typedef struct sr_name_service {
    uint16_t port;
    const char *name;
} sr_name_service;

static const sr_name_service sr_name_services[] = {
    {  137, "NetBIOS name service" },
    {  138, "NetBIOS datagram service" },
    { 1900, "SSDP" },
    { 5353, "mDNS" },
    { 5355, "LLMNR" },
};

/** What one packet turned out to be. */
typedef struct sr_packet {
    int af;
    int proto;
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    uint32_t tcp_flags;
    uint8_t payload[SR_PAYLOAD_MAX];
    size_t payload_len;
} sr_packet;

/** TCP flags, as the ASN.1 representation numbers them. */
#define SR_TCP_FIN  0x01
#define SR_TCP_SYN  0x02
#define SR_TCP_ACK  0x10

/** Add a finding unless the same one has been added already. */
static void
sr_report(tapi_sniffrules_session *session, tapi_cybersec_severity severity,
          const char *check, const char *subject, const char *detail_fmt, ...)
{
    te_string key = TE_STRING_INIT;
    va_list ap;
    te_string detail = TE_STRING_INIT;

    te_string_append(&key, "%s|%s", check, subject);
    if (te_kvpairs_get_nth(&session->seen, key.ptr, 0) != NULL)
    {
        te_string_free(&key);
        return;
    }
    te_kvpair_push(&session->seen, key.ptr, "1");
    te_string_free(&key);

    va_start(ap, detail_fmt);
    te_string_append_va(&detail, detail_fmt, ap);
    va_end(ap);

    tapi_cybersec_report_add(session->report, severity, check, subject,
                             "%s", te_string_value(&detail));
    te_string_free(&detail);
}

/** Print an address without its port. */
static void
sr_addr2str(const struct sockaddr *addr, te_string *dest)
{
    char text[INET6_ADDRSTRLEN] = "?";

    if (addr->sa_family == AF_INET)
    {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)addr)->sin_addr,
                  text, sizeof(text));
    }
    else if (addr->sa_family == AF_INET6)
    {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)addr)->sin6_addr,
                  text, sizeof(text));
    }

    te_string_append(dest, "%s", text);
}

static uint16_t
sr_port(const struct sockaddr_storage *addr)
{
    if (addr->ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)addr)->sin_port);

    return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
}

/** Case-insensitive search for @p needle in a payload. */
static bool
sr_payload_has(const sr_packet *pkt, const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    if (pkt->payload_len < needle_len)
        return false;

    for (i = 0; i + needle_len <= pkt->payload_len; i++)
    {
        if (strncasecmp((const char *)pkt->payload + i, needle,
                        needle_len) == 0)
            return true;
    }

    return false;
}

/** Does the payload start with this command, as a line does? */
static bool
sr_payload_starts_with(const sr_packet *pkt, const char *prefix)
{
    size_t len = strlen(prefix);

    return pkt->payload_len >= len &&
           strncasecmp((const char *)pkt->payload, prefix, len) == 0;
}

/** Traffic on a port that has no transport security. */
static void
sr_rule_cleartext_proto(tapi_sniffrules_session *session,
                        const sr_packet *pkt)
{
    uint16_t src = sr_port(&pkt->src);
    uint16_t dst = sr_port(&pkt->dst);
    size_t i;

    for (i = 0; i < TE_ARRAY_LEN(sr_cleartext_ports); i++)
    {
        const sr_cleartext *entry = &sr_cleartext_ports[i];
        te_string subject = TE_STRING_INIT;

        if (entry->proto != pkt->proto ||
            (entry->port != src && entry->port != dst))
            continue;

        te_string_append(&subject, "%s/%u",
                         pkt->proto == IPPROTO_TCP ? "tcp" : "udp",
                         entry->port);
        sr_report(session,
                  entry->carries_credentials ? TAPI_CYBERSEC_SEV_HIGH
                                             : TAPI_CYBERSEC_SEV_MEDIUM,
                  "traffic.cleartext-protocol", subject.ptr,
                  "%s traffic was seen, and %s carries everything in the "
                  "clear", entry->name, entry->name);
        te_string_free(&subject);
        break;
    }
}

/** Credentials on the wire. The value is never recorded. */
static void
sr_rule_cleartext_creds(tapi_sniffrules_session *session,
                        const sr_packet *pkt)
{
    uint16_t dst = sr_port(&pkt->dst);
    te_string subject = TE_STRING_INIT;
    const char *what = NULL;

    if (pkt->proto != IPPROTO_TCP || pkt->payload_len == 0)
        return;

    if (sr_payload_has(pkt, "authorization: basic"))
        what = "HTTP basic authentication";
    else if ((dst == 21 || dst == 110) &&
             (sr_payload_starts_with(pkt, "PASS ") ||
              sr_payload_starts_with(pkt, "USER ")))
        what = "a login command";
    else if (dst == 143 && sr_payload_has(pkt, " LOGIN "))
        what = "an IMAP LOGIN command";

    if (what == NULL)
        return;

    te_string_append(&subject, "tcp/%u", dst);
    sr_report(session, TAPI_CYBERSEC_SEV_CRITICAL,
              "traffic.cleartext-credentials", subject.ptr,
              "%s crossed the wire unprotected; the value is deliberately "
              "not recorded here", what);
    te_string_free(&subject);
}

/**
 * A handshake older than TLS 1.2.
 *
 * The ServerHello is what is judged, because it carries what was
 * actually agreed. TLS 1.3 keeps @c 0x0303 in that field and moves the
 * real version into an extension, so this rule sees TLS 1.3 as 1.2 and
 * reports neither: what it catches is TLS 1.1 and older, which is the
 * finding worth having.
 */
static void
sr_rule_weak_tls(tapi_sniffrules_session *session, const sr_packet *pkt)
{
    const uint8_t *p = pkt->payload;
    te_string subject = TE_STRING_INIT;
    uint16_t src = sr_port(&pkt->src);

    if (pkt->proto != IPPROTO_TCP)
        return;

    /* An SSLv2 hello, which no current stack should ever emit. */
    if (pkt->payload_len >= 3 && (p[0] & 0x80) != 0 && p[2] == 0x01)
    {
        te_string_append(&subject, "tcp/%u", src);
        sr_report(session, TAPI_CYBERSEC_SEV_HIGH, "traffic.weak-tls",
                  subject.ptr, "an SSLv2 handshake was seen");
        te_string_free(&subject);
        return;
    }

    if (pkt->payload_len < 11 || p[0] != 0x16 || p[1] != 0x03)
        return;

    /* Record: type, version, length; then handshake: type, length24. */
    if (p[5] != 0x02)
        return;

    if (p[9] == 0x03 && p[10] >= 0x03)
        return;

    te_string_append(&subject, "tcp/%u", src);
    sr_report(session, TAPI_CYBERSEC_SEV_HIGH, "traffic.weak-tls",
              subject.ptr,
              "the server agreed to protocol version %u.%u, which is older "
              "than TLS 1.2", p[9], p[10]);
    te_string_free(&subject);
}

/** DNS anyone on the path can read and rewrite. */
static void
sr_rule_plaintext_dns(tapi_sniffrules_session *session, const sr_packet *pkt)
{
    uint16_t src = sr_port(&pkt->src);
    uint16_t dst = sr_port(&pkt->dst);
    te_string subject = TE_STRING_INIT;
    te_string server = TE_STRING_INIT;

    if (src != 53 && dst != 53)
        return;

    sr_addr2str(CONST_SA(dst == 53 ? &pkt->dst : &pkt->src), &server);
    te_string_append(&subject, "%s/53",
                     pkt->proto == IPPROTO_TCP ? "tcp" : "udp");
    sr_report(session, TAPI_CYBERSEC_SEV_MEDIUM, "traffic.plaintext-dns",
              subject.ptr,
              "name resolution with %s is neither authenticated nor "
              "encrypted", server.ptr);
    te_string_free(&subject);
    te_string_free(&server);
}

/** Protocols that announce the host to the whole segment. */
static void
sr_rule_name_leak(tapi_sniffrules_session *session, const sr_packet *pkt)
{
    uint16_t src = sr_port(&pkt->src);
    uint16_t dst = sr_port(&pkt->dst);
    size_t i;

    if (pkt->proto != IPPROTO_UDP)
        return;

    for (i = 0; i < TE_ARRAY_LEN(sr_name_services); i++)
    {
        const sr_name_service *entry = &sr_name_services[i];
        te_string subject = TE_STRING_INIT;

        if (entry->port != src && entry->port != dst)
            continue;

        te_string_append(&subject, "udp/%u", entry->port);
        sr_report(session, TAPI_CYBERSEC_SEV_LOW, "traffic.name-leak",
                  subject.ptr,
                  "%s tells every host on the segment what this one is "
                  "called and what it is looking for", entry->name);
        te_string_free(&subject);
        break;
    }
}

/**
 * A connection started towards somewhere the policy does not allow.
 *
 * Only the first packet of a conversation is judged - a TCP SYN without
 * an ACK, or any UDP packet - so a flow produces one finding and
 * traffic that merely passes the interface in the other direction is
 * not mistaken for the device reaching out.
 */
static void
sr_rule_unexpected_egress(tapi_sniffrules_session *session,
                          const sr_packet *pkt)
{
    te_string subject = TE_STRING_INIT;
    te_string where = TE_STRING_INIT;

    if (session->opt.egress == NULL)
        return;

    if (pkt->proto == IPPROTO_TCP &&
        ((pkt->tcp_flags & SR_TCP_SYN) == 0 ||
         (pkt->tcp_flags & SR_TCP_ACK) != 0))
        return;

    if (tapi_egress_policy_allows(session->opt.egress, pkt->proto,
                                  CONST_SA(&pkt->dst)))
        return;

    sr_addr2str(CONST_SA(&pkt->dst), &where);
    te_string_append(&subject, "%s/%s:%u",
                     pkt->proto == IPPROTO_TCP ? "tcp" : "udp", where.ptr,
                     sr_port(&pkt->dst));
    sr_report(session, TAPI_CYBERSEC_SEV_HIGH, "traffic.unexpected-egress",
              subject.ptr,
              "a conversation was started towards it and no rule allows it");
    te_string_free(&subject);
    te_string_free(&where);
}

/** Read one address out of a captured packet. */
static bool
sr_read_addr(const asn_value *packet, int af, bool source,
             struct sockaddr_storage *dst, const char *port_label)
{
    const char *addr_label;
    uint8_t raw[16];
    size_t raw_len = (af == AF_INET) ? 4 : 16;
    uint32_t port = 0;

    if (af == AF_INET)
        addr_label = source ? "pdus.1.#ip4.src-addr.#plain"
                            : "pdus.1.#ip4.dst-addr.#plain";
    else
        addr_label = source ? "pdus.1.#ip6.src-addr.#plain"
                            : "pdus.1.#ip6.dst-addr.#plain";

    if (asn_read_value_field(packet, raw, &raw_len, addr_label) != 0)
        return false;

    if (asn_read_uint32(packet, &port, port_label) != 0)
        return false;

    memset(dst, 0, sizeof(*dst));
    dst->ss_family = (sa_family_t)af;

    if (af == AF_INET)
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

    return true;
}

/** Turn a captured packet into what the rules need. */
static bool
sr_decode(const asn_value *packet, const sr_channel *channel, sr_packet *pkt)
{
    const char *transport = (channel->proto == IPPROTO_TCP) ? "tcp" : "udp";
    te_string src_label = TE_STRING_INIT;
    te_string dst_label = TE_STRING_INIT;
    int payload_len;
    bool ok;

    memset(pkt, 0, sizeof(*pkt));
    pkt->af = channel->af;
    pkt->proto = channel->proto;

    te_string_append(&src_label, "pdus.0.#%s.src-port.#plain", transport);
    te_string_append(&dst_label, "pdus.0.#%s.dst-port.#plain", transport);

    ok = sr_read_addr(packet, channel->af, true, &pkt->src, src_label.ptr) &&
         sr_read_addr(packet, channel->af, false, &pkt->dst, dst_label.ptr);

    te_string_free(&src_label);
    te_string_free(&dst_label);

    if (!ok)
        return false;

    if (channel->proto == IPPROTO_TCP)
        (void)asn_read_uint32(packet, &pkt->tcp_flags,
                              "pdus.0.#tcp.flags.#plain");

    payload_len = asn_get_length(packet, "payload.#bytes");
    if (payload_len > 0)
    {
        size_t len = (size_t)payload_len;

        if (len > sizeof(pkt->payload))
            len = sizeof(pkt->payload);

        if (asn_read_value_field(packet, pkt->payload, &len,
                                 "payload.#bytes") == 0)
            pkt->payload_len = len;
    }

    return true;
}

/** Context handed to the per-packet callback. */
typedef struct sr_cb_ctx {
    tapi_sniffrules_session *session;
    const sr_channel *channel;
} sr_cb_ctx;

static void
sr_packet_cb(asn_value *packet, void *user_data)
{
    sr_cb_ctx *ctx = user_data;
    tapi_sniffrules_session *session = ctx->session;
    unsigned int rules = session->opt.rules;
    sr_packet pkt;

    session->packets++;

    if (!sr_decode(packet, ctx->channel, &pkt))
    {
        asn_free_value(packet);
        return;
    }

    if ((rules & TAPI_SNIFFRULE_CLEARTEXT_PROTO) != 0)
        sr_rule_cleartext_proto(session, &pkt);
    if ((rules & TAPI_SNIFFRULE_CLEARTEXT_CREDS) != 0)
        sr_rule_cleartext_creds(session, &pkt);
    if ((rules & TAPI_SNIFFRULE_WEAK_TLS) != 0)
        sr_rule_weak_tls(session, &pkt);
    if ((rules & TAPI_SNIFFRULE_PLAINTEXT_DNS) != 0)
        sr_rule_plaintext_dns(session, &pkt);
    if ((rules & TAPI_SNIFFRULE_NAME_LEAK) != 0)
        sr_rule_name_leak(session, &pkt);
    if ((rules & TAPI_SNIFFRULE_UNEXPECTED_EGRESS) != 0)
        sr_rule_unexpected_egress(session, &pkt);

    asn_free_value(packet);
}

/** Build the accept-everything pattern for one channel. */
static te_errno
sr_make_pattern(const sr_channel *channel, asn_value **pattern)
{
    te_string text = TE_STRING_INIT;
    int syms = 0;
    te_errno rc;

    te_string_append(&text, "{{ pdus { %s:{}, %s:{}, eth:{} } }}",
                     channel->proto == IPPROTO_TCP ? "tcp" : "udp",
                     channel->af == AF_INET ? "ip4" : "ip6");

    rc = asn_parse_value_text(text.ptr, ndn_traffic_pattern, pattern, &syms);
    if (rc != 0)
        ERROR("Cannot build the capture pattern '%s': %r", text.ptr, rc);

    te_string_free(&text);

    return rc;
}

/* See description in tapi_sniffrules.h */
te_errno
tapi_sniffrules_start(const char *ta, const char *ifname,
                      const tapi_sniffrules_opt *opt,
                      tapi_sniffrules_session **session)
{
    static const int families[] = { AF_INET, AF_INET6 };
    static const int protos[] = { IPPROTO_TCP, IPPROTO_UDP };
    tapi_sniffrules_session *result;
    size_t f;
    size_t p;
    te_errno rc;

    if (opt == NULL)
        opt = &tapi_sniffrules_default_opt;

    if ((opt->rules & TAPI_SNIFFRULE_UNEXPECTED_EGRESS) != 0 &&
        opt->egress == NULL)
    {
        ERROR("The egress rule needs a policy to check against");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    result = TE_ALLOC(sizeof(*result));
    result->ta = TE_STRDUP(ta);
    result->opt = *opt;
    te_kvpair_init(&result->seen);

    rc = rcf_ta_create_session(ta, &result->sid);
    if (rc != 0)
    {
        ERROR("Cannot create an RCF session on TA %s: %r", ta, rc);
        goto fail;
    }

    for (f = 0; f < TE_ARRAY_LEN(families); f++)
    {
        if ((families[f] == AF_INET && !opt->ipv4) ||
            (families[f] == AF_INET6 && !opt->ipv6))
            continue;

        for (p = 0; p < TE_ARRAY_LEN(protos); p++)
        {
            sr_channel *channel = &result->channels[result->n_channels];
            asn_value *pattern = NULL;

            channel->af = families[f];
            channel->proto = protos[p];
            channel->csap = CSAP_INVALID_HANDLE;

            /*
             * Everything on the interface, including what this host
             * sends: traffic leaving the device is half of what the
             * rules are about.
             */
            rc = tapi_tcp_udp_ip_eth_csap_create(ta, result->sid, ifname,
                                                 TAD_ETH_RECV_ALL,
                                                 NULL, NULL, channel->af,
                                                 channel->proto,
                                                 NULL, NULL, -1, -1,
                                                 &channel->csap);
            if (rc != 0)
            {
                ERROR("Cannot create a capture CSAP on %s of TA %s: %r",
                      ifname, ta, rc);
                goto fail;
            }

            /*
             * Counted as soon as the CSAP exists, so that the cleanup
             * path destroys it even if the capture never starts.
             */
            result->n_channels++;

            rc = sr_make_pattern(channel, &pattern);
            if (rc != 0)
                goto fail;

            rc = tapi_tad_trrecv_start(ta, result->sid, channel->csap,
                                       pattern, TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_PACKETS);
            asn_free_value(pattern);
            if (rc != 0)
            {
                ERROR("Cannot start capturing on %s of TA %s: %r", ifname,
                      ta, rc);
                goto fail;
            }
        }
    }

    *session = result;

    return 0;

fail:
    (void)tapi_sniffrules_stop(result, NULL);

    return rc;
}

/* See description in tapi_sniffrules.h */
te_errno
tapi_sniffrules_stop(tapi_sniffrules_session *session,
                     tapi_cybersec_report *report)
{
    te_errno result_rc = 0;
    size_t i;

    if (session == NULL)
        return 0;

    session->report = report;
    session->packets = 0;

    for (i = 0; i < session->n_channels; i++)
    {
        sr_channel *channel = &session->channels[i];
        sr_cb_ctx ctx = { .session = session, .channel = channel };
        tapi_tad_trrecv_cb_data *cb_data = NULL;
        unsigned int num = 0;
        te_errno rc;

        if (channel->csap == CSAP_INVALID_HANDLE)
            continue;

        if (report != NULL)
            cb_data = tapi_tad_trrecv_make_cb_data(sr_packet_cb, &ctx);

        rc = tapi_tad_trrecv_stop(session->ta, session->sid, channel->csap,
                                  cb_data, &num);
        if (rc != 0 && result_rc == 0)
            result_rc = rc;

        free(cb_data);

        rc = tapi_tad_csap_destroy(session->ta, session->sid, channel->csap);
        if (rc != 0 && result_rc == 0)
            result_rc = rc;
    }

    if (report != NULL)
        RING("Traffic rules: %u packets examined", session->packets);

    te_kvpair_fini(&session->seen);
    free(session->ta);
    free(session);

    return result_rc;
}
