# DNSLOOKUP

DNSLOOKUP is a Linux command-line DNS lookup tool written in C. It is intended
for learning and training: use it to practice querying DNS and interpreting
common DNS records. Only query domains and networks you own or are authorized
to use.

## Features

- Look up A, AAAA, MX, NS, TXT, CNAME, and SOA records
- Perform reverse lookups for IPv4 and IPv6 addresses
- Trace DNS resolution with `dig`
- Retrieve domain registration information with `whois`
- Run concurrent lookups from a file
- Display results as a table or JSON
- Show record TTL values

## Requirements

You need a Linux system, GCC, GNU Make, the C library development files, and
pthread support. The `dig` command is needed for DNS tracing, and `whois` is
needed for WHOIS queries.

On Fedora:

```bash
sudo dnf install gcc make glibc-devel bind-utils whois
```

On Debian or Ubuntu:

```bash
sudo apt install build-essential libc6-dev dnsutils whois
```

## Build

From the project directory, run:

```bash
make
```

This builds the `dnslookup` executable. To remove the executable and object
files:

```bash
make clean
```

## Usage

Run a DNS record lookup by providing a domain. A records are queried by
default:

```bash
./dnslookup example.com
```

Choose a record type with `-t`:

```bash
./dnslookup example.com -t MX
./dnslookup example.com -t AAAA
./dnslookup example.com -t TXT
```

Supported record types are `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, and `SOA`.

### Look up domains from a file

The included [`domains.txt`](./domains.txt) file is a sample batch input. Put
one domain on each line. Blank lines and lines starting with `#` are ignored.
For example:

```text
# Domains for a training exercise
example.com
example.org
```

Run a batch lookup with `-b` and provide the file path:

```bash
./dnslookup -b domains.txt
```

You can choose the record type and number of worker threads. The thread count
is limited to 32:

```bash
./dnslookup -b domains.txt -t MX -T 4
```

You can also create your own input file and pass its path:

```bash
./dnslookup -b my-domains.txt -t A
```

### Other commands

Look up the reverse DNS name for an IP address:

```bash
./dnslookup -r 8.8.8.8
./dnslookup -r 2001:4860:4860::8888
```

Trace DNS resolution or query WHOIS information:

```bash
./dnslookup --trace example.com
./dnslookup --whois example.com
```

Use `-j` to print lookup results as JSON. For example:

```bash
./dnslookup example.com -t MX -j
./dnslookup -b domains.txt -t A -j
```

To see the command summary and options:

```bash
./dnslookup --help
```

## Training and responsible use

Use this project to learn how DNS record types, TTLs, reverse lookups, and
resolution tracing work. Start with domains supplied for your training
environment or domains you are permitted to query. Public DNS queries are
visible to the DNS resolvers and networks handling them; do not use this tool
to scan or query systems without authorization.
