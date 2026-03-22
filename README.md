# ft_nmap

A multi-threaded TCP/IP port scanner written in C, implementing the core scanning techniques of the original nmap. Built as a 42 school project.

## Requirements

- Linux (raw sockets + libpcap)
- `libpcap-dev`
- Root privileges or `CAP_NET_RAW`

## Build

```bash
make              # Build binary
make sanitize     # Build with ASan/LSan/UBSan
make own          # Set SUID root (run without sudo)
make re           # Full rebuild
make clean        # Remove object files
make fclean       # Remove objects and binary
```

## Usage

```bash
sudo ./ft_nmap --ip <target> [OPTIONS]
# or after make own:
./ft_nmap --ip <target> [OPTIONS]
```

| Option | Argument | Description |
|--------|----------|-------------|
| `--ip` | IPv4 / hostname | Target to scan |
| `--file` | path | File with one target per line |
| `--ports` | port spec | Ports to scan (default: 1-1024) |
| `--scan` | type(s) | Scan types, comma-separated (default: all) |
| `--speedup` | 0-250 | Number of threads (0 = sequential) |
| `--verbose` | — | Enable info logging |
| `--debug` | — | Enable debug logging |
| `--help` | — | Print usage |

### Port specification

```
80          single port
1-1024      range
22,80,443   list
1-100,443   mixed
```

### Scan types

| Type | Protocol | Detection method |
|------|----------|-----------------|
| `SYN` | TCP | SYN+ACK → open, RST → closed |
| `ACK` | TCP | RST → unfiltered, no reply → filtered |
| `FIN` | TCP | RST → closed, no reply → open\|filtered |
| `NULL` | TCP | RST → closed, no reply → open\|filtered |
| `XMAS` | TCP | RST → closed, no reply → open\|filtered |
| `UDP` | UDP | ICMP port-unreach → closed, reply → open |

## Architecture

```
main()
  ├─ scan_create()          allocate scan context
  ├─ scan_opts_parse()      parse CLI
  └─ for each target:
       ├─ scan_resolve_target()   DNS/IP resolution
       ├─ scan_detect_source()    detect outbound IP via routing
       ├─ probe_list_create()     generate probes (ports × scan types)
       └─ scan_run()
            ├─ sequential (--speedup 0)
            │    └─ scan_thread_run()
            └─ parallel (--speedup N)
                 └─ scan_thread_dispatch() → pthread_create × N
                      └─ scan_thread_run() per thread
```

### Sliding window (scan_thread_run)

Each thread runs an independent sliding window loop:

1. **Send phase** — fill window up to `WINDOW_SIZE` (20) concurrent probes
2. **Receive phase** — `select()` with 10 ms timeout, drain packets via `pcap_next_ex()`
3. **Timeout phase** — after 2 s, retry up to `MAX_RETRIES` (3) times, then mark result

### Lock-free threading

Each thread gets an exclusive source port range (`sport_base` to `sport_base + 1023`). A BPF filter scoped to that range ensures each thread captures only its own responses — no mutexes needed.

## Port states

| State | Meaning |
|-------|---------|
| `open` | Service accepting connections |
| `closed` | Port reachable, no service |
| `filtered` | No response (firewall likely) |
| `unfiltered` | Reachable, state unknown (ACK scan) |
| `open\|filtered` | Cannot distinguish (FIN/NULL/XMAS) |

## Example output

```
Scan configurations
Target IP-Address : 45.33.32.156
No of ports to scan : 4
Scans to be performed : SYN ACK
No of threads : 2
Scanning...

Scan took 8.07 sec
Scan results for scanme.nmap.org (45.33.32.156)
PORT       STATE          SERVICE
22/syn     open           ssh
80/syn     open           http

25/syn     filtered       smtp
443/syn    closed         https
22/ack     unfiltered     ssh
80/ack     unfiltered     http
25/ack     filtered       smtp
443/ack    unfiltered     https
```

## Dependencies

| Library | Purpose |
|---------|---------|
| libpcap | Packet capture |
| libpthread | POSIX threads |
| libm | Math |
| libft | Internal linked-list utilities |
