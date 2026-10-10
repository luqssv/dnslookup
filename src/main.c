#define _GNU_SOURCE

#include "dnslookup.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define MAX_INPUTS 4096
#define DEFAULT_THREADS 4
#define MAX_THREADS 32


typedef struct {

    char *items[MAX_INPUTS];

    size_t count;
    size_t next;

    int threads;

    const char *type;

    LookupResult *results;

    pthread_mutex_t lock;

} BatchContext;


typedef struct {

    BatchContext *ctx;

} WorkerArg;


int is_valid_domain(const char *domain)
{
    if (!domain)
        return 0;

    if (!*domain)
        return 0;

    if (strlen(domain) >= 253)
        return 0;


    for (const char *p = domain; *p; p++)
    {
        if (isspace((unsigned char)*p))
            return 0;

        if ((unsigned char)*p < 32)
            return 0;
    }

    return 1;
}


static void usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s <domain> [-t TYPE] [-j]\n", prog);
    printf("  %s -r <IP> [-j]\n", prog);
    printf("  %s -b <file> [-t TYPE] [-T threads] [-j]\n", prog);
    printf("  %s --trace <domain>\n", prog);
    printf("  %s --whois <domain>\n\n", prog);
    printf("Types:\n");
    printf("  A\n  AAAA\n  MX\n  NS\n  TXT\n  CNAME\n  SOA\n\n");
    printf("Examples:\n");
    printf("  %s example.com -t MX\n", prog);
    printf("  %s example.com -t TXT -j\n", prog);
    printf("  %s -r 8.8.8.8\n", prog);
    printf("  %s -b domains.txt -t A -T 8\n", prog);
    printf("  %s --trace example.com\n", prog);
    printf("  %s --whois example.com\n", prog);
}
static void *worker(void *arg)
{
    WorkerArg *w = (WorkerArg *)arg;
    BatchContext *ctx = w->ctx;
    while (1) {
        pthread_mutex_lock(&ctx->lock);
        size_t i = ctx->next++;
        pthread_mutex_unlock(&ctx->lock);
        if (i >= ctx->count)
            break;
        dns_lookup(ctx->items[i], ctx->type, &ctx->results[i]);
    }
    return NULL;
}
static int read_batch(const char *filename, BatchContext *ctx)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    char line[512];
    while (ctx->count < MAX_INPUTS && fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line;
        while (isspace((unsigned char)*p))
            p++;
        if (!*p || *p == '#')
            continue;

        char *end = p + strlen(p);
        while (end > p && isspace((unsigned char)end[-1]))
            *--end = '\0';

        if (!is_valid_domain(p))
            continue;

        ctx->items[ctx->count] = strdup(p);
        if (!ctx->items[ctx->count])
            break;
        ctx->count++;
    }

    fclose(fp);
    return 0;
}


static int run_batch(const char *file, const char *type, int threads, int json)
{
    BatchContext ctx = {0};
    ctx.type = type;
    ctx.threads = threads;
    ctx.results = calloc(MAX_INPUTS, sizeof(LookupResult));
    if (!ctx.results)
        return 1;

    if (read_batch(file, &ctx) < 0) {
        free(ctx.results);
        return 1;
    }

    if (!ctx.count) {
        fprintf(stderr, "No valid domains found.\n");
        free(ctx.results);
        return 1;
    }

    pthread_mutex_init(&ctx.lock, NULL);
    pthread_t tids[MAX_THREADS];
    WorkerArg arg = {.ctx = &ctx};

    for (int i = 0; i < threads; i++)
        pthread_create(&tids[i], NULL, worker, &arg);

    for (int i = 0; i < threads; i++)
        pthread_join(tids[i], NULL);

    pthread_mutex_destroy(&ctx.lock);

    if (json) {
        printf("[\n");
        for (size_t i = 0; i < ctx.count; i++)
            print_result_json(&ctx.results[i], i + 1 < ctx.count);
        printf("]\n");
    } else {
        for (size_t i = 0; i < ctx.count; i++)
            print_result_table(&ctx.results[i]);
    }

    for (size_t i = 0; i < ctx.count; i++)
        free(ctx.items[i]);
    free(ctx.results);
    return 0;
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        print_banner();
        usage(argv[0]);
        return 1;
    }

    const char *type = "A", *batch_file = NULL, *reverse_ip = NULL, *domain = NULL;
    int json = 0, threads = DEFAULT_THREADS, json_requested = 0;

    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-j"))
            json_requested = 1;

    if (!json_requested)
        print_banner();

    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argv[0]);
        return 0;
    }

    if (!strcmp(argv[1], "--trace")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        if (!is_valid_domain(argv[2])) {
            fprintf(stderr, "Invalid domain.\n");
            return 1;
        }

        char *const args[] = {"dig", "+trace", argv[2], NULL};
        printf("\n=== DNS TRACE: %s ===\n\n", argv[2]);
        int rc = run_external_capture(args, 1);
        if (rc == 127)
            fprintf(stderr, "dig is not installed. On Fedora: sudo dnf install bind-utils\n");
        return rc;
    }

    if (!strcmp(argv[1], "--whois")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        if (!is_valid_domain(argv[2])) {
            fprintf(stderr, "Invalid domain.\n");
            return 1;
        }

        char *const args[] = {"whois", argv[2], NULL};
        printf("\n=== WHOIS: %s ===\n\n", argv[2]);
        int rc = run_external_capture(args, 1);
        if (rc == 127)
            fprintf(stderr, "whois is not installed. On Fedora: sudo dnf install whois\n");
        return rc;
    }

    if (!strcmp(argv[1], "-r")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }

        reverse_ip = argv[2];
        for (int i = 3; i < argc; i++)
            if (!strcmp(argv[i], "-j"))
                json = 1;

        LookupResult r;
        reverse_lookup(reverse_ip, &r);

        if (json) {
            printf("[\n");
            print_result_json(&r, 0);
            printf("]\n");
        } else {
            print_result_table(&r);
        }
        return r.status < 0;
    }

    if (!strcmp(argv[1], "-b")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }

        batch_file = argv[2];
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "-j"))
                json = 1;
            else if (!strcmp(argv[i], "-t") && i + 1 < argc)
                type = argv[++i];
            else if (!strcmp(argv[i], "-T") && i + 1 < argc)
                threads = atoi(argv[++i]);
        }

        if (threads < 1)
            threads = 1;
        if (threads > MAX_THREADS)
            threads = MAX_THREADS;

        return run_batch(batch_file, type, threads, json);
    }

    domain = argv[1];
    if (!is_valid_domain(domain)) {
        fprintf(stderr, "Invalid domain.\n");
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-j"))
            json = 1;
        else if (!strcmp(argv[i], "-t") && i + 1 < argc)
            type = argv[++i];
    }

    LookupResult r;
    dns_lookup(domain, type, &r);

    if (json) {
        printf("[\n");
        print_result_json(&r, 0);
        printf("]\n");
    } else {
        print_result_table(&r);
    }

    return r.status < 0;
}