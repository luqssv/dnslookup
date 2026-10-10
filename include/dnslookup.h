#ifndef DNSLOOKUP_H
#define DNSLOOKUP_H

#include <stddef.h>

#define MAX_RECORDS 128
#define MAX_TEXT 2048

typedef struct {
    char type[8];
    char value[MAX_TEXT];
    unsigned int ttl;
} DnsRecord;

typedef struct {
    char domain[256];
    char requested_type[8];

    DnsRecord records[MAX_RECORDS];
    size_t count;

    int status;
    char error[256];
} LookupResult;

void dns_lookup(const char *domain, const char *type, LookupResult *result);
void reverse_lookup(const char *ip, LookupResult *result);
void print_result_table(const LookupResult *result);
void print_result_json(const LookupResult *result, int comma_after);

void print_banner(void);

int run_external_capture(char *const argv[], int show_output);

int is_valid_domain(const char *domain);

#endif