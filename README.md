# Pcapture

A cross-platform C++17 command-line Ethernet packet sniffer. Captures live
traffic from a network interface via libpcap (Linux/macOS) or Npcap (Windows),
or replays a saved `.pcap` file (`-r`), decodes Ethernet, 802.1Q VLAN tags
(Q-in-Q up to 2 deep), IPv4 with IPv6 extension-header walking, ARP, and
TCP / UDP / ICMP / ICMPv6, and renders to human, compact, or JSON Lines
output.

The capture, decode, and output stages run on separate threads connected by a
bounded queue, so a slow terminal or filesystem cannot stall the kernel ring.

## Architecture

```
+-----------+   +----------+   +---------+   +--------+   +-----------+
|  libpcap  |-->| Bounded  |-->| Decoder |-->| Filter |-->| Formatter |--> stdout / file
|  capture  |   | Queue<F> |   |         |   |        |   |           |
+-----------+   +----------+   +---------+   +--------+   +-----------+
capture thread ^  cap=N              decode + format thread
               |
      SIGINT / count / duration -> pcap_breakloop()
```

Source layout:

| Path | Responsibility |
|------|----------------|
| [src/cli/](src/cli/)         | argv parsing (cxxopts), validation, `Config` |
| [src/capture/](src/capture/) | `pcap_findalldevs`, `pcap_open_live`, RAII `PcapHandle`, BPF filter |
| [src/decode/](src/decode/)   | per-protocol parsers + dispatch table → `DecodedPacket` |
| [src/filter/](src/filter/)   | post-decode `key=value` predicate filter |
| [src/format/](src/format/)   | `Formatter` interface + Human / Compact / JSON |
| [src/pipeline/](src/pipeline/) | `BoundedQueue<T>` + threaded capture-decode-format pipeline |
| [src/util/](src/util/)       | signal handling, hexdump |
| [tests/](tests/)             | GoogleTest unit tests for every layer |


## Build

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

Or set the `NPCAP_SDK_DIR` environment variable instead of `-DPCAP_ROOT`.

### Sanitizer build (recommended for development)

```sh
cmake -B build-asan -DENABLE_SANITIZERS=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Usage

```
pcapture [flags]

  -i, --interface <name>         live capture from interface (mutually exclusive with -r)
  -r, --read <file.pcap>         offline replay from a saved pcap file
  -L, --list-interfaces          enumerate available interfaces and exit
  -f, --filter <bpf>             kernel-side BPF filter (e.g. "tcp port 443")
  -m, --match <key=value>        decoded-side filter, repeatable (AND'd)
                                 keys: proto vlan ip src dst port sport dport
  -F, --format human|compact|json
  -v, -vv                        verbose multi-line output; -vv adds hex dump
  -c, --count <N>                stop after N packets (0 = unlimited)
  -d, --duration <S>             stop after S seconds
  -s, --snaplen <bytes>          capture up to N bytes per frame (default 65535)
      --queue-capacity <N>       bounded queue size (default 8192)
      --back-pressure drop-newest|drop-oldest|block
      --check-checksums          validate IPv4/TCP/UDP/ICMP/ICMPv6; bad ones noted
      --allow-non-ethernet       allow non-DLT_EN10MB datalinks (decoder may misparse)
  -o, --output <path>            redirect packet output to a file
  -h, --help / -V, --version
```

## Examples

### List interfaces

```
$ sudo ./build/pcapture --list-interfaces
eth0  [up running]
    description: Ethernet interface
    ipv4: 192.168.1.42
    ipv6: fe80::a00:27ff:fe14:38b
lo    [loopback up running]
    ipv4: 127.0.0.1
    ipv6: ::1
```

JSON form:

```
$ sudo ./build/pcapture --list-interfaces --format json | jq .
[
  {
    "name": "eth0",
    "loopback": false,
    "up": true, "running": true,
    "addresses": [{"family":"ipv4","address":"192.168.1.42"}, ...]
  },
  ...
]
```

### Live capture

Default human format, count-limited, BPF + decoded-side filter:

```
$ sudo ./build/pcapture -i eth0 -c 5 -f "tcp" -m proto=tcp -m dport=443
aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66 192.168.1.42 > 142.250.80.46 ttl=64 TCP 56432 > 443 [S] win=64240 caplen=74
11:22:33:44:55:66 > aa:bb:cc:dd:ee:ff 142.250.80.46 > 192.168.1.42 ttl=128 TCP 443 > 56432 [SA] win=65535 caplen=74
...
```

JSON Lines, pipeable into `jq`:

```
$ sudo ./build/pcapture -i eth0 -F json -c 1 | jq .
{
  "ts_us": 1730800000123456,
  "caplen": 74,
  "len": 74,
  "eth": {"src":"aa:bb:cc:dd:ee:ff","dst":"11:22:33:44:55:66","ethertype":2048},
  "ipv4": {"src":"192.168.1.42","dst":"142.250.80.46","proto":6,"ttl":64,"total_length":60},
  "tcp": {"sport":56432,"dport":443,"seq":1,"ack":0,"flags":2,"window":64240}
}
```

Replay a saved pcap with checksum validation:

```
$ ./build/pcapture -r samples/web.pcap --check-checksums -F json | jq -r '.notes[]?' | sort -u
bad tcp checksum         # only seen on locally-originated traffic captured before NIC offload
```

Verbose with hex dump (`-vv`):

```
$ sudo ./build/pcapture -i lo -c 1 -vv
00:00:00:00:00:00 > 00:00:00:00:00:00 127.0.0.1 > 127.0.0.1 ttl=64 ICMP type=8 code=0 caplen=98
    eth: src=00:00:00:00:00:00 dst=00:00:00:00:00:00 ethertype=0x800
    ipv4: 127.0.0.1 -> 127.0.0.1 proto=1 ttl=64 total=84
    icmp: type=8 code=0
    00000000  00 00 00 00 00 00 00 00  00 00 00 00 08 00 45 00  |..............E.|
    00000010  00 54 0c 79 40 00 40 01  30 22 7f 00 00 01 7f 00  |.T.y@.@.0"......|
    ...
```

Pre-recorded transcripts: see [examples/](examples/).

### Shutdown summary (stderr)

```
pcapture: shutdown summary
  packets captured  : 1284
  packets decoded   : 1284
  packets filtered  : 312
  packets printed   : 972
  queue drops       : 0
  kernel received   : 1284
  kernel dropped    : 0
  iface dropped     : 0
```

## Filter grammar

Each `--match` argument is a single `key=value` predicate. Multiple `--match`
arguments are AND'd. Keys:

| Key     | Value                  | Matches                                     |
|---------|------------------------|---------------------------------------------|
| `proto` | `tcp`/`udp`/`icmp`/`icmpv6`/`arp` | L4 (or L3 for ARP) protocol         |
| `vlan`  | `0..4095`              | any VLAN tag's VID                          |
| `ip`    | IPv4 or IPv6 literal   | matches L3 src OR dst (also ARP spa/tpa)    |
| `src`   | IPv4 or IPv6 literal   | L3 source address                           |
| `dst`   | IPv4 or IPv6 literal   | L3 destination address                      |
| `port`  | `0..65535`             | TCP/UDP source OR destination port          |
| `sport` | `0..65535`             | TCP/UDP source port                         |
| `dport` | `0..65535`             | TCP/UDP destination port                    |



