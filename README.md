# cidrwall

`cidrwall` watches Blockmerge's newline-delimited mixed IPv4/IPv6 CIDR files and enforces them with
nftables, XDP, or both. nftables rules can cover input, forward, and output traffic. XDP rules drop
packets by source address at ingress, before the network stack distinguishes local input from
forwarded traffic. The daemon never invokes the `nft` executable.

Each backend stages updates independently and activates them atomically. nftables uses unreferenced
generation sets; XDP uses two pinned LPM-trie slots and switches a control-map selector only after
the inactive slot is complete. A parse, capacity, or kernel error leaves that backend's active
generation unchanged and does not prevent the other backend from accepting a valid reload.

The nftables table contains separate interval sets for inbound/outbound IPv4/IPv6 traffic and base
chains for input, forward, and output. XDP maps and links are pinned beneath
`/sys/fs/bpf/cidrwall` by default. Normal SIGINT/SIGTERM shutdown preserves both backends unless
cleanup is explicitly enabled.

## Configuration

Start with [config/cidrwall.toml](config/cidrwall.toml). Zones can be defined directly in it:

```toml
[zones]
WAN = ["eth0"]
LOCAL = { interfaces = [], local = true }
LAN = ["eth1"]
```

Alternatively, omit `[zones]` and set `zones = "/data/zones.json"` in `[files]` (or pass
`--zones`/`CIDRWALL_ZONES`). [config/zones.example.json](config/zones.example.json) accepts either
the shown map or `{ "zones": [{ "name": "WAN", "interfaces": ["eth0"] }] }`. Inline and file
definitions are mutually exclusive; an explicit CLI/environment zones path selects the file.
Zone alternatives are expanded as separate nftables rules (OR); ingress and egress constraints in
one forward mapping are paired as a cross product (AND).

XDP mappings live in their own section and only accept the inbound blocklist:

```toml
[xdp]
mode = "auto"                       # auto, native, or generic
pin_path = "/sys/fs/bpf/cidrwall"
ipv4_max_entries = 5000000
ipv6_max_entries = 5000000
cleanup_on_exit = false

[[xdp.rules]]
blocklist = "inbound"
ingress_zones = ["WAN"]
```

`auto` tries native/driver XDP first and falls back to generic/SKB XDP only when native mode is not
supported. Missing interfaces fail startup. cidrwall will not replace a foreign XDP program, and
requires a kernel with pinnable BPF links so attachments survive daemon restarts. Two configured
LPM tries exist per address family, so capacity should account for both slots. The default is five
million prefixes per map and can be reduced for smaller systems.

An XDP ingress interface may not also appear in an nftables inbound input/forward rule by default,
because that commonly indicates accidental duplicate policy. Set
`xdp.allow_nftables_overlap = true` when the overlap is intentional. nftables outbound mappings and
inbound mappings on other interfaces remain available alongside XDP.

Unknown zones, interface-less non-local zones, local zones in forward rules, and chain-inappropriate
fields are rejected before netlink is opened. Flowtables are queried directly over netlink. If one
contains any protected interface, startup/reconciliation fails unless
`allow_flowtable_bypass = true` is explicitly set.

`[files].inbound` and `[files].outbound` are optional when no rule mapping references the
corresponding blocklist. A referenced direction must have a configured path, and a configured path
must exist when that direction is loaded. Unused directions are not staged, watched, or
reconciled. An explicitly configured empty file remains valid and activates empty IPv4/IPv6 sets
for that direction.

All file paths, table settings, timing settings, and the flowtable override have CLI flags and
`CIDRWALL_*` environment overrides. Use `cidrwall --help` for their exact names. Validate and show
the expanded mappings without changing the firewall:

```console
cidrwall --config ./config/cidrwall.toml --check
```

Blocklist syntax remains producer-neutral:

```text
# generated 2026-08-18T12:00:00Z
192.0.2.0/24
2001:db8::/32
```

Blank lines and comments are ignored. Any other line must be a normalized CIDR. cidrwall requires
Blockmerge's canonical ordering: numerically ordered, disjoint IPv4 entries followed by numerically
ordered, disjoint IPv6 entries. Duplicates, overlaps, host bits, and IPv4 entries after IPv6 are
rejected. Adjacent CIDRs are coalesced into one nftables interval while streaming.

`populate_batch_elements` bounds the number of nftables interval-boundary elements held in each
population transaction (default `2000`). `batch_page_bytes` controls the page size within that
bounded transaction (default `131072`). Each direction is staged, health-checked, atomically
activated, and cleaned up before replacement of the other direction begins. This temporarily
retains only the old and new generations for one direction at a time. Userspace memory is bounded
by the configured population size instead of the complete list.

Tables created by releases before the generation layout are intentionally incompatible. If the
configured table exists without the current layout marker, cidrwall exits without modifying it;
remove that table explicitly before starting the new release.

Every staged generation is checked with the same set-presence and logical-element-count checks
used by periodic reconciliation before its rules are activated. A rejected reload retains the
known-good active generation. If startup cannot stage, verify, and activate both directions,
cidrwall exits nonzero instead of running without a tracked active generation; any pre-existing
nftables table remains preserved for inspection.

Set `cleanup_on_exit = true` independently in `[nftables]` and `[xdp]` to remove that backend's
owned kernel state after SIGINT/SIGTERM or another orderly return. Both options default to false.
For one-shot administrative cleanup, use:

```console
cidrwall --config ./config/cidrwall.toml --cleanup xdp
cidrwall --config ./config/cidrwall.toml --cleanup nftables
cidrwall --config ./config/cidrwall.toml --cleanup all
```

Cleanup verifies cidrwall's layout marker before removing state; it does not remove unrecognized
tables or pinned maps.

## Container

The container needs the host network namespace, `CAP_NET_ADMIN`, and `CAP_BPF` for XDP on kernels
that separate BPF privilege. It also needs the host bpffs mounted at `/sys/fs/bpf`. An nftables-only
configuration needs only `CAP_NET_ADMIN`. Mount the Blockmerge output directory read-only so
inotify can observe destination renames.
Both Debian and Alpine images install only the `libnftnl` and `libmnl` runtime libraries—`nft` is
not installed. Build both variants with Docker Bake, or build either Dockerfile directly:

```console
docker buildx bake
docker build -f Dockerfile.debian -t cidrwall:debian .
docker build -f Dockerfile.alpine -t cidrwall:alpine .
```

## Tests

```console
cargo binstall bpf-linker
rustup toolchain install nightly --profile minimal --component rust-src
cargo test
sudo ./tests/netns.sh
```

The Rust suite covers parsing, interval/CIDR encoding, configuration rendering, overlap rejection,
atomic rename event classification, failed-stage retention, bounded population, and
incompatible-layout rejection. The namespace test exercises nftables rules without touching the
host ruleset. Building the default feature set also compiles and embeds the Aya eBPF object;
`--no-default-features` remains available for a build with neither native netlink nor XDP.

## Publishing

All three crates use the same version and are published in dependency order:
`cidrwall-common`, `cidrwall-ebpf`, then `cidrwall`. The eBPF crate is a source package used by
`cidrwall`'s build script; its default target is a small host-verifiable library, while the actual
BPF target is enabled only by the build script's `program` feature.

The first crates.io publication must be made locally with a crates.io API token because trusted
publishing cannot claim a package name that does not exist yet. The bootstrap uses normal Cargo
verification, so install the same native libraries, nightly `rust-src`, and `bpf-linker` required
by a default build. Commit the release version and run:

```console
./scripts/publish-initial.sh --execute
```

The script requires a clean tracked worktree, skips packages already published at that version,
waits for each package to become visible in the crates.io index, and then publishes its dependent.
Configure GitHub trusted publishing for all three crate names after this bootstrap. Subsequent
releases are handled by release-plz as one version group; only `cidrwall` creates the Git tag and
GitHub release.
