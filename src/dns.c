#define _GNU_SOURCE

#include "dnslookup.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void set_error(LookupResult *r, const char *msg)
{
    r->status = -1;
    snprintf(r->error, sizeof(r->error), "%s", msg);
}

static void add_record(LookupResult *r, const char *type, const char *value, unsigned int ttl)
{
    if (r->count >= MAX_RECORDS)
        return;

    snprintf(r->records[r->count].type, sizeof(r->records[r->count].type), "%s", type);
    snprintf(r->records[r->count].value, sizeof(r->records[r->count].value), "%s", value);
    r->records[r->count].ttl = ttl;
    r->count++;
}

static int name_from_rdata(const unsigned char *msg, const unsigned char *rdata, size_t msg_len, char *out, size_t out_sz)
{
    int n = ns_name_uncompress(msg, msg + msg_len, rdata, out, out_sz);
    return n < 0 ? -1 : 0;
}

static void parse_txt(const unsigned char *rdata, size_t rdlen, char *out, size_t out_sz)
{
    size_t p = 0, used = 0;
    out[0] = '\0';

    while (p < rdlen && used + 1 < out_sz) {
        unsigned int len = rdata[p++];
        if (p + len > rdlen)
            break;

        if (used && used + 1 < out_sz)
            out[used++] = ' ';

        for (unsigned int i = 0; i < len && used + 1 < out_sz; i++) {
            unsigned char c = rdata[p + i];
            if (c == '"' || c == '\\') {
                if (used + 2 < out_sz)
                    out[used++] = '\\';
            }
            out[used++] = (c >= 32 && c <= 126) ? c : '.';
        }

        p += len;
    }

    out[used] = '\0';
}

static void parse_answer(const unsigned char *msg, size_t msg_len, ns_msg *handle, ns_rr *rr, const char *wanted, LookupResult *result)
{
    const unsigned char *rdata = ns_rr_rdata(*rr);
    size_t rdlen = ns_rr_rdlen(*rr);
    unsigned int ttl = ns_rr_ttl(*rr);
    int type = ns_rr_type(*rr);
    char value[MAX_TEXT];
    value[0] = '\0';

    switch (type) {
        case ns_t_a:
            if (rdlen == 4 && inet_ntop(AF_INET, rdata, value, sizeof(value)))
                add_record(result, "A", value, ttl);
            break;

        case ns_t_aaaa:
            if (rdlen == 16 && inet_ntop(AF_INET6, rdata, value, sizeof(value)))
                add_record(result, "AAAA", value, ttl);
            break;

        case ns_t_mx: {
            if (rdlen >= 3) {
                unsigned int pref = ns_get16(rdata);
                char host[NS_MAXDNAME];
                if (name_from_rdata(msg, rdata + 2, msg_len, host, sizeof(host)) == 0) {
                    snprintf(value, sizeof(value), "%u %s", pref, host);
                    add_record(result, "MX", value, ttl);
                }
            }
            break;
        }

        case ns_t_ns:
            if (name_from_rdata(msg, rdata, msg_len, value, sizeof(value)) == 0)
                add_record(result, "NS", value, ttl);
            break;

        case ns_t_cname:
            if (name_from_rdata(msg, rdata, msg_len, value, sizeof(value)) == 0)
                add_record(result, "CNAME", value, ttl);
            break;

        case ns_t_txt:
            parse_txt(rdata, rdlen, value, sizeof(value));
            add_record(result, "TXT", value, ttl);
            break;

        case ns_t_soa: {
            char mname[NS_MAXDNAME], rname[NS_MAXDNAME];
            int n1 = ns_name_uncompress(msg, msg + msg_len, rdata, mname, sizeof(mname));
            if (n1 < 0 || (size_t)n1 >= rdlen)
                break;

            const unsigned char *p = rdata + n1;
            int n2 = ns_name_uncompress(msg, msg + msg_len, p, rname, sizeof(rname));
            if (n2 < 0)
                break;

            p += n2;
            if ((size_t)(p - rdata) + 20 > rdlen)
                break;

            unsigned long serial = ns_get32(p);
            unsigned long refresh = ns_get32(p + 4);
            unsigned long retry = ns_get32(p + 8);
            unsigned long expire = ns_get32(p + 12);
            unsigned long minimum = ns_get32(p + 16);

            snprintf(value, sizeof(value), "%s %s serial=%lu refresh=%lu retry=%lu expire=%lu minimum=%lu",
                     mname, rname, serial, refresh, retry, expire, minimum);
            add_record(result, "SOA", value, ttl);
            break;
        }

        default:
            (void)wanted;
            (void)handle;
            break;
    }
}

static int type_to_code(const char *type)
{
    if (!strcasecmp(type, "A")) return ns_t_a;
    if (!strcasecmp(type, "AAAA")) return ns_t_aaaa;
    if (!strcasecmp(type, "MX")) return ns_t_mx;
    if (!strcasecmp(type, "NS")) return ns_t_ns;
    if (!strcasecmp(type, "TXT")) return ns_t_txt;
    if (!strcasecmp(type, "CNAME")) return ns_t_cname;
    if (!strcasecmp(type, "SOA")) return ns_t_soa;
    return -1;
}

void dns_lookup(const char *domain, const char *type, LookupResult *result)
{
    memset(result, 0, sizeof(*result));
    snprintf(result->domain, sizeof(result->domain), "%s", domain);
    snprintf(result->requested_type, sizeof(result->requested_type), "%s", type);

    int qtype = type_to_code(type);
    if (qtype < 0) {
        set_error(result, "Unsupported DNS record type");
        return;
    }

    unsigned char answer[65536];
    int len = res_query(domain, ns_c_in, qtype, answer, sizeof(answer));
    if (len < 0) {
        if (h_errno == HOST_NOT_FOUND)
            set_error(result, "NXDOMAIN / host not found");
        else if (h_errno == TRY_AGAIN)
            set_error(result, "DNS server temporarily unavailable");
        else if (h_errno == NO_DATA)
            set_error(result, "No records of this type");
        else
            set_error(result, hstrerror(h_errno));
        return;
    }

    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        set_error(result, "Could not parse DNS response");
        return;
    }

    int ancount = ns_msg_count(handle, ns_s_an);
    for (int i = 0; i < ancount; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0)
            parse_answer(answer, (size_t)len, &handle, &rr, type, result);
    }

    if (result->count == 0)
        set_error(result, "No records found in the answer section");
}

void reverse_lookup(const char *ip, LookupResult *result)
{
    memset(result, 0, sizeof(*result));
    snprintf(result->domain, sizeof(result->domain), "%s", ip);
    snprintf(result->requested_type, sizeof(result->requested_type), "PTR");

    struct sockaddr_storage ss;
    socklen_t len;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        len = sizeof(*v4);
    } else if (inet_pton(AF_INET6, ip, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        len = sizeof(*v6);
    } else {
        set_error(result, "Invalid IPv4/IPv6 address");
        return;
    }

    char host[NI_MAXHOST];
    int rc = getnameinfo((struct sockaddr *)&ss, len, host, sizeof(host), NULL, 0, NI_NAMEREQD);
    if (rc != 0) {
        set_error(result, gai_strerror(rc));
        return;
    }

    add_record(result, "PTR", host, 0);
}
