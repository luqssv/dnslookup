#include "dnslookup.h"
#include <stdio.h>
#include <string.h>


#define C_RESET "\033[0m"
#define C_CYAN "\033[36m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED "\033[31m"
#define C_BLUE "\033[34m"

void print_banner(void)
{
    printf(C_CYAN
           "██████╗ ███╗   ██╗███████╗██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗\n"
           "██╔══██╗████╗  ██║██╔════╝██║     ██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗\n"
           "██║  ██║██╔██╗ ██║███████╗██║     ██║   ██║██║   ██║█████╔╝ ██║   ██║██████╔╝\n"
           "██║  ██║██║╚██╗██║╚════██║██║     ██║   ██║██║   ██║██╔═██╗ ██║   ██║██╔═══╝\n"
           "██████╔╝██║ ╚████║███████║███████╗╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝██║\n"
           "╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝\n"
           C_RESET
           "\n  DNS reconnaissance and lookup utility - C / Linux\n\n");
}

static const char *type_color(const char *type)
{
    if (!strcmp(type, "A") || !strcmp(type, "AAAA")) return C_GREEN;
    if (!strcmp(type, "MX") || !strcmp(type, "NS")) return C_BLUE;
    if (!strcmp(type, "TXT")) return C_YELLOW;
    return C_CYAN;
}

void print_result_table(const LookupResult *r)
{
    printf("%sDomain:%s %s\n", C_CYAN, C_RESET, r->domain);
    printf("%sQuery:%s  %s\n", C_CYAN, C_RESET, r->requested_type);

    if (r->status < 0) {
        printf("%s[ERROR]%s %s\n\n", C_RED, C_RESET, r->error);
        return;
    }

    printf("+----------+-------+------------------------------------------------------------+\n");
    printf("| %-8s | %-5s | %-58s |\n", "TYPE", "TTL", "VALUE");
    printf("+----------+-------+------------------------------------------------------------+\n");

    for (size_t i = 0; i < r->count; i++)
        printf("| %s%-8s%s | %-5u | %-58.58s |\n", type_color(r->records[i].type), r->records[i].type, C_RESET, r->records[i].ttl, r->records[i].value);

    printf("+----------+-------+------------------------------------------------------------+\n\n");
}

static void json_escape(const char *src, char *dst, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < n; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= n) break;
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n') {
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c == '\r') {
            dst[j++] = '\\';
            dst[j++] = 'r';
        } else if (c == '\t') {
            dst[j++] = '\\';
            dst[j++] = 't';
        } else if (c >= 32) {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

void print_result_json(const LookupResult *r, int comma_after)
{
    char domain[512], type[64], error[512], value[MAX_TEXT * 2];
    json_escape(r->domain, domain, sizeof(domain));
    json_escape(r->requested_type, type, sizeof(type));

    printf("  {\n    \"domain\": \"%s\",\n    \"type\": \"%s\",\n    \"status\": %d,\n", domain, type, r->status);
    if (r->status < 0) {
        json_escape(r->error, error, sizeof(error));
        printf("    \"error\": \"%s\",\n", error);
    }

    printf("    \"records\": [");
    for (size_t i = 0; i < r->count; i++) {
        json_escape(r->records[i].value, value, sizeof(value));
        printf("{\"type\":\"%s\",\"ttl\":%u,\"value\":\"%s\"}%s",
               r->records[i].type, r->records[i].ttl, value, i + 1 < r->count ? "," : "");
    }
    printf("]\n  }%s\n", comma_after ? "," : "");
}