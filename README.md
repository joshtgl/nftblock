# nftblock

`nftblock` watches Blockmerge's newline-delimited mixed IPv4/IPv6 CIDR files and owns a single
`inet nftblock` table. It streams canonical input into bounded, unreferenced generation sets and
then atomically switches stable dispatch chains to the completed generation. A parse, allocation,
or kernel error leaves the active generation unchanged. The daemon never invokes the `nft`
executable.

The table contains separate interval sets for inbound/outbound IPv4/IPv6 traffic and base chains
for input, forward, and output. Normal SIGINT/SIGTERM shutdown deliberately preserves the table.

## Configuration

Start with [config/nftblock.toml](config/nftblock.toml). Zones can be defined directly in it:

```toml
[zones]
WAN = ["eth0"]
LOCAL = { interfaces = [], local = true }
LAN = ["eth1"]
```

Alternatively, omit `[zones]` and set `zones = "/data/zones.json"` in `[files]` (or pass
`--zones`/`NFTBLOCK_ZONES`). [config/zones.example.json](config/zones.example.json) accepts either
the shown map or `{ "zones": [{ "name": "WAN", "interfaces": ["eth0"] }] }`. Inline and file
definitions are mutually exclusive; an explicit CLI/environment zones path selects the file.
Zone alternatives are expanded as separate nftables rules (OR); ingress and egress constraints in
one forward mapping are paired as a cross product (AND).

Unknown zones, interface-less non-local zones, local zones in forward rules, and chain-inappropriate
fields are rejected before netlink is opened. Flowtables are queried directly over netlink. If one
contains any protected interface, startup/reconciliation fails unless
`allow_flowtable_bypass = true` is explicitly set.

All file paths, table settings, timing settings, and the flowtable override have CLI flags and
`NFTBLOCK_*` environment overrides. Use `nftblock --help` for their exact names. Validate and show
the expanded mappings without changing the firewall:

```console
nftblock --config ./config/nftblock.toml --check
```

Blocklist syntax remains producer-neutral:

```text
# generated 2026-08-18T12:00:00Z
192.0.2.0/24
2001:db8::/32
```

Blank lines and comments are ignored. Any other line must be a normalized CIDR. nftblock requires
Blockmerge's canonical ordering: numerically ordered, disjoint IPv4 entries followed by numerically
ordered, disjoint IPv6 entries. Duplicates, overlaps, host bits, and IPv4 entries after IPv6 are
rejected. Adjacent CIDRs are coalesced into one nftables interval while streaming.

`populate_batch_elements` bounds the number of nftables interval-boundary elements held in each
population transaction (default `100000`). `batch_page_bytes` controls pages within that bounded
transaction. Reloads temporarily retain both generations in kernel memory, but userspace memory is
bounded by the configured population size instead of the complete list.

Tables created by releases before the generation layout are intentionally incompatible. If the
configured table exists without the current layout marker, nftblock exits without modifying it;
remove that table explicitly before starting the new release.

## Container

The container needs the host network namespace and `CAP_NET_ADMIN`; it does not need privileged
mode. Mount the Blockmerge output directory read-only so inotify can observe destination renames.
Both Debian and Alpine images install only the `libnftnl` and `libmnl` runtime libraries—`nft` is
not installed. Build both variants with Docker Bake, or build either Dockerfile directly:

```console
docker buildx bake
docker build -f Dockerfile.debian -t nftblock:debian .
docker build -f Dockerfile.alpine -t nftblock:alpine .
```

## Tests

```console
cargo test
sudo ./tests/netns.sh
```

The Rust suite covers parsing, interval encoding, configuration rendering, atomic rename event
classification, failed-stage retention, bounded multi-page construction, and incompatible-layout
rejection. The namespace test exercises native chunked input, forward, and output rules without
touching the host ruleset.

An ignored release-mode test streams and serializes 4,228,762 entries and enforces a 256 MiB Linux
peak-RSS budget:

```console
cargo test --release netlink::native::tests::streams_4_2m_entries_under_256_mib -- --ignored --exact --nocapture
```
