<p align="center">
  <img src="docs/assets/logo.png" alt="Pcapture logo" width="180" />
</p>

<h1 align="center">Pcapture</h1>

<p align="center"><em>A focused, layered Ethernet packet sniffer for the command line.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-17-FCB316?style=flat-square" alt="C++17" />
  <img src="https://img.shields.io/badge/build-CMake-6DACDE?style=flat-square" alt="CMake" />
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-6D9A45?style=flat-square" alt="Platforms" />
</p>

---

## Overview

Pcapture is a portable C++17 command-line sniffer that runs on **Linux, macOS,
and Windows** from the same source tree. It captures Ethernet frames from a
local interface (libpcap on Linux/macOS, Npcap on Windows) or replays a saved
`.pcap` file, decodes Layer 2–4 headers, and renders the result as human,
compact, or JSON Lines output — identically on every platform.

## Why Pcapture?

- **Drop-in JSON Lines pipelines.** Decoded frames stream straight into `jq`,
  `awk`, log shippers, or any line-oriented store — no XML, no protobuf, no
  custom parsers.
- **Headless and dependency-light.** A single binary plus libpcap/Npcap. Fits
  containers, jump hosts, embedded gateways, and CI runners where a GUI
  sniffer is impractical.
- **Cross-platform parity.** The same CLI, decoders, and output formats on
  Linux, macOS, and Windows — so capture scripts written on one OS run
  unchanged on the others.
- **Readable reference implementation.** A layered, three-thread pipeline
  (capture → decode → format) that's small enough to read end-to-end and
  extend with a new protocol or output format in a single file.

## Key features

- **Live capture** via libpcap/Npcap, plus offline `.pcap` replay (`-r`).
- **Decoders** for Ethernet, 802.1Q VLAN tags (Q-in-Q, recursion capped at 8 levels), IPv4, IPv6 with extension-header walking, ARP, TCP, UDP, ICMP, ICMPv6.
- **Three output formats**: column table (`human`), one-liner (`compact`), JSON Lines (`json`).
- **Two-stage filtering**: kernel-side BPF (`-f`) and decoded-side `key=value` predicates (`-m`, repeatable, AND'd).
- **Three-thread pipeline** (capture / decoder / formatter) joined by two bounded queues with selectable back-pressure (`drop-newest` / `drop-oldest` / `block`).
- Optional **checksum validation** for IPv4/TCP/UDP/ICMP/ICMPv6.
- Verbose / hex-dump modes (`-v` / `-vv`).
- Graceful shutdown with capture and kernel summary on stderr.

## Architecture

Single-direction pipeline. Capture, decoding, and output run on three separate
threads connected by two bounded queues, so neither parsing cost nor a slow
terminal/filesystem can stall the kernel ring.

```
+-----------+   +----------+   +-----------+   +----------+   +-----------+
|  libpcap  |-->|   Q1     |-->| Decoder   |-->|   Q2     |-->| Formatter |--> stdout / file
|  / Npcap  |   | RawFrame |   | + Filter  |   | Decoded  |   |           |
+-----------+   +----------+   +-----------+   +----------+   +-----------+
 capture thread                decoder thread                  formatter thread
```

- **Capture thread** owns `pcap_dispatch`. The libpcap callback pushes
  `RawFrame { timestamp, seq, captured_len, original_len, bytes }` into Q1.
- **Decoder thread** pops Q1, runs the registry-driven decoder chain
  (Ethernet → VLAN → L3 → L4), applies the `--match` predicate filter, and
  pushes a `DecodedPacket` into Q2. Filtered packets never cross Q2.
- **Formatter thread** pops Q2, renders via the configured `Formatter`
  (human / compact / JSON), and writes to the sink.

Both queues honour `--queue-capacity` and `--back-pressure`. Drops on either
queue are tallied into the single `queue drops` summary row. Shutdown
propagates in pipeline order: capture exits → Q1 closes → decoder drains and
closes Q2 → formatter drains.

## Installation

### Linux / macOS

```sh
sudo apt install build-essential cmake libpcap-dev   # Debian / Ubuntu
brew install cmake libpcap                            # macOS

cmake -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Windows

Install [Npcap](https://npcap.com/) **with the SDK component**, then:

```powershell
cmake -B build -DPCAP_ROOT="C:/Path/To/Npcap-SDK"
cmake --build build --config Release
```

`NPCAP_SDK_DIR` works as an alternative to `-DPCAP_ROOT`.

### Development build with sanitizers (Linux/macOS)

```sh
cmake -B build-asan -DENABLE_SANITIZERS=ON
cmake --build build-asan -j
```

## Usage

> Live capture requires elevated privileges: `CAP_NET_RAW` / `CAP_NET_ADMIN` on Linux, administrator on Windows, or BPF device access on macOS/BSD. Offline replay (`-r`) does not.

```
pcapture [flags]

  -i, --interface <name>         live capture (mutually exclusive with -r)
  -r, --read <file.pcap>         offline replay
  -L, --list-interfaces          enumerate interfaces and exit
  -f, --filter <bpf>             kernel-side BPF filter
  -m, --match <key=value>        decoded-side filter, repeatable (AND'd)
                                 keys: proto vlan ip src dst port sport dport
  -F, --format human|compact|json
      --time none|relative|absolute|epoch
      --color auto|always|never  honours NO_COLOR
  -v, -vv                        verbose / hex dump
  -c, --count <N>                stop after N packets
  -d, --duration <S>             stop after S seconds
  -s, --snaplen <bytes>          per-frame capture cap (default 65535)
      --queue-capacity <N>       bounded queue size (default 8192)
      --back-pressure drop-newest|drop-oldest|block
      --check-checksums          validate L3/L4 checksums
      --allow-non-ethernet       permit non-DLT_EN10MB datalinks
  -o, --output <path>            write packet output to file
  -h, --help / -V, --version
```

### Filter grammar (`--match`)

| Key                          | Value                                     | Matches                                |
|------------------------------|-------------------------------------------|----------------------------------------|
| `proto`                      | `tcp` / `udp` / `icmp` / `icmpv6` / `arp` | L4, or L3 for ARP                      |
| `vlan`                       | `0..4095`                                 | any VLAN tag's VID                     |
| `ip`                         | IPv4 or IPv6 literal                      | L3 src OR dst (also ARP spa/tpa)       |
| `src` / `dst`                | IPv4 or IPv6 literal                      | L3 source / destination                |
| `port` / `sport` / `dport`   | `0..65535`                                | TCP/UDP either-side / source / dest    |

## Example output

Human (default), 5 frames, BPF + decoded-side filter:

```
$ sudo ./build/pcapture -i eth0 -c 5 -f "tcp" -m proto=tcp -m dport=443
  Δt           proto    src                          dst                          flags   win     size
  +0.000000    TCP      192.168.1.42:54812        →  104.16.124.96:443            [S]     64240    74 B
  +0.013421    TCP      104.16.124.96:443         →  192.168.1.42:54812           [SA]    65535    74 B
  +0.013506    TCP      192.168.1.42:54812        →  104.16.124.96:443            [A]       512    66 B
```

JSON Lines, pipeable into `jq`:

```
$ sudo ./build/pcapture -i eth0 -F json -c 1 -m dport=443 | jq -c .
{"ts_us":1730802512345678,"caplen":74,"len":74,"eth":{"src":"de:ad:be:ef:00:01","dst":"00:13:5f:1c:7d:50","ethertype":2048},"ipv4":{"src":"192.168.1.42","dst":"93.184.216.34","proto":6,"ttl":64,"total_length":60},"tcp":{"sport":58432,"dport":443,"seq":2891241334,"ack":0,"flags":2,"window":64240}}
```

Verbose (`-v`) and hex-dump (`-vv`) transcripts, plus a `--list-interfaces`
sample, live in [examples/](examples/).

### Shutdown summary (stderr)

```
=== pcapture summary ===
  captured            1284
  decoded             1284
  filtered             312   (24.3% of decoded)
  displayed            972
  queue drops            0

=== kernel ===
  received            1284
  dropped                0   (0.0% of received)
  iface dropped          0
```

## Repository structure

| Path | Responsibility |
|------|----------------|
| [src/cli/](src/cli/)             | argv parsing (cxxopts), validation, `Config` |
| [src/capture/](src/capture/)     | libpcap/Npcap binding, interface enumeration, signal handling |
| [src/parser/](src/parser/)       | decoder dispatch table and parse orchestration |
| [src/protocols/](src/protocols/) | per-protocol parsers (Ethernet, VLAN, IPv4/6, ARP, TCP, UDP, ICMP/v6) |
| [src/model/](src/model/)         | `DecodedPacket` and layer types |
| [src/filter/](src/filter/)       | post-decode `key=value` predicate filter |
| [src/output/](src/output/)       | `Formatter` interface + human / compact / JSON, color, table, hex dump |
| [src/app/](src/app/)             | `BoundedQueue<T>` and threaded pipeline orchestration |
| [src/common/](src/common/)       | checksum helpers, byte-reader utilities |
| [tests/](tests/)                 | GoogleTest unit tests for every layer |
| [examples/](examples/)           | pre-recorded output transcripts |

## Known limitations & roadmap

Each current limitation is paired with the planned improvement that addresses it.

| Limitation today | Planned improvement |
|------------------|---------------------|
| **Capture-file output**: replays `.pcap` but does not write them; PCAP-NG unsupported in either direction. `-o` writes a single file with no rotation. | `.pcap` / `.pcapng` export and long-running capture rotation (size- or time-based). |
| **Single interface per run**: `-i` accepts one device. | Multi-interface capture with per-interface tagging and merged timestamps. |
| **No reassembly**: TCP streams and IPv6 fragments are decoded per-frame only. | TCP stream tracking, retransmission detection, and IP fragment reassembly. |
| **L4-only dissection**: HTTP, DNS, DHCP, TLS, NTP, PTP stop at L4; payload bytes are not emitted. | Extend protocol coverage with DNS, DHCP, HTTP headers, TLS metadata, NTP, and PTP. |
| **AND-only filter grammar**: `-m` predicates are combined with implicit AND; no `OR`, comparisons, or value lists. | Boolean expressions, comparisons, value lists, and reusable filter profiles. |
| **No runtime statistics**: only an end-of-run summary is produced. | Live top talkers, protocol counters, bandwidth, queue usage, and drop-reason breakdowns. |
| **Three output formats only** (`human`, `compact`, `json`). | Additional formats: CSV, Markdown, YAML, and summary reports. |
| **Static pipeline tuning**: queue capacity and back-pressure are configurable, but no batching or benchmark mode. | Batched output, queue telemetry, benchmark mode, and optional high-performance backends. |

Other planned work: fuzz / malformed-packet / golden-output tests and
cross-platform CI; config files, capture profiles, shell completion, packaged
releases, and troubleshooting docs.

