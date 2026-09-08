use crate::{
    blocklist::{self, AddressPrefix},
    config::{Config, Xdp as XdpConfig, XdpMode as ConfigMode, open_blocklist},
};
use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, EbpfLoader,
    maps::{
        Array, MapData,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{
        Xdp, XdpMode,
        links::{FdLink, PinnedLink},
    },
};
use cidrwall_common::{Control, LAYOUT_VERSION, SLOT_COUNT};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fs,
    path::{Path, PathBuf},
};

const CONTROL: &str = "CONTROL";
const IPV4_A: &str = "IPV4_A";
const IPV4_B: &str = "IPV4_B";
const IPV6_A: &str = "IPV6_A";
const IPV6_B: &str = "IPV6_B";
const MAP_NAMES: [&str; 5] = [CONTROL, IPV4_A, IPV4_B, IPV6_A, IPV6_B];
const PROGRAM: &str = "cidrwall";
const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cidrwall"));

type V4Trie = LpmTrie<MapData, [u8; 4], u8>;
type V6Trie = LpmTrie<MapData, [u8; 16], u8>;

pub struct XdpManager {
    config: XdpConfig,
    interfaces: BTreeMap<u32, String>,
    _ebpf: Ebpf,
    control: Array<MapData, Control>,
    ipv4_a: V4Trie,
    ipv4_b: V4Trie,
    ipv6_a: V6Trie,
    ipv6_b: V6Trie,
    links: BTreeMap<u32, PinnedLink>,
}

impl XdpManager {
    pub fn new(config: &Config, interface_names: BTreeSet<String>) -> Result<Self> {
        let xdp = config.xdp.clone();
        fs::create_dir_all(&xdp.pin_path)
            .with_context(|| format!("create XDP pin directory {}", xdp.pin_path.display()))?;
        fs::create_dir_all(link_dir(&xdp))
            .with_context(|| format!("create XDP link directory {}", link_dir(&xdp).display()))?;

        let interfaces = resolve_interfaces(interface_names)?;
        let mut loader = EbpfLoader::new();
        loader
            .default_map_pin_directory(&xdp.pin_path)
            .map_max_entries(IPV4_A, xdp.ipv4_max_entries)
            .map_max_entries(IPV4_B, xdp.ipv4_max_entries)
            .map_max_entries(IPV6_A, xdp.ipv6_max_entries)
            .map_max_entries(IPV6_B, xdp.ipv6_max_entries);
        let mut ebpf = loader.load(OBJECT).context("load cidrwall XDP object")?;

        let mut control: Array<_, Control> = ebpf
            .take_map(CONTROL)
            .context("XDP object has no CONTROL map")?
            .try_into()?;
        let current = control.get(&0, 0)?;
        if current.layout_version == 0 {
            control.set(
                0,
                Control {
                    layout_version: LAYOUT_VERSION,
                    active_slot: 0,
                },
                0,
            )?;
        } else if current.layout_version != LAYOUT_VERSION || current.active_slot >= SLOT_COUNT {
            bail!(
                "{} contains an incompatible XDP map layout (version={}, active_slot={})",
                xdp.pin_path.display(),
                current.layout_version,
                current.active_slot
            );
        }

        let ipv4_a = take_v4(&mut ebpf, IPV4_A)?;
        let ipv4_b = take_v4(&mut ebpf, IPV4_B)?;
        let ipv6_a = take_v6(&mut ebpf, IPV6_A)?;
        let ipv6_b = take_v6(&mut ebpf, IPV6_B)?;
        let links = open_owned_links(&xdp, interfaces.keys().copied().collect())?;

        let program: &mut Xdp = ebpf
            .program_mut(PROGRAM)
            .context("XDP object has no cidrwall program")?
            .try_into()?;
        program.load().context("load cidrwall XDP program")?;

        let mut manager = Self {
            config: xdp,
            interfaces,
            _ebpf: ebpf,
            control,
            ipv4_a,
            ipv4_b,
            ipv6_a,
            ipv6_b,
            links,
        };
        manager.reconcile_links()?;
        Ok(manager)
    }

    pub fn reload(&mut self, config: &Config, reason: &str) -> Result<()> {
        let active = self.control.get(&0, 0)?.active_slot;
        let inactive = 1 - active;
        self.clear_slot(inactive)?;

        let path = config
            .blocklist_path(crate::config::Direction::Inbound)
            .context("inbound blocklist is not configured for XDP")?;
        let reader = open_blocklist(path)?;
        let mut ipv4 = 0u64;
        let mut ipv6 = 0u64;
        let result = blocklist::stream_chunks(
            reader,
            self.config.populate_batch_elements as usize,
            |chunk| {
                for interval in chunk {
                    for prefix in blocklist::interval_prefixes(*interval) {
                        match prefix {
                            AddressPrefix::V4 {
                                address,
                                prefix_len,
                            } => {
                                if ipv4 >= u64::from(self.config.ipv4_max_entries) {
                                    bail!(
                                        "XDP IPv4 map capacity exceeded ({})",
                                        self.config.ipv4_max_entries
                                    );
                                }
                                self.v4_mut(inactive).insert(
                                    &Key::new(u32::from(prefix_len), address.octets()),
                                    1,
                                    0,
                                )?;
                                ipv4 += 1;
                            }
                            AddressPrefix::V6 {
                                address,
                                prefix_len,
                            } => {
                                if ipv6 >= u64::from(self.config.ipv6_max_entries) {
                                    bail!(
                                        "XDP IPv6 map capacity exceeded ({})",
                                        self.config.ipv6_max_entries
                                    );
                                }
                                self.v6_mut(inactive).insert(
                                    &Key::new(u32::from(prefix_len), address.octets()),
                                    1,
                                    0,
                                )?;
                                ipv6 += 1;
                            }
                        }
                    }
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            if let Err(clear) = self.clear_slot(inactive) {
                log::error!("failed to clear rejected XDP staging slot: {clear:#}");
            }
            return Err(error).with_context(|| format!("stage XDP blocklist {}", path.display()));
        }

        self.control.set(
            0,
            Control {
                layout_version: LAYOUT_VERSION,
                active_slot: inactive,
            },
            0,
        )?;
        if let Err(error) = self.clear_slot(active) {
            log::error!("obsolete XDP slot cleanup deferred: {error:#}");
        }
        log::info!(
            "activated XDP blocklist: reason={reason} path={} ipv4_prefixes={ipv4} ipv6_prefixes={ipv6} slot={inactive}",
            path.display()
        );
        Ok(())
    }

    pub fn reconcile(&mut self) -> Result<()> {
        let state = self.control.get(&0, 0)?;
        if state.layout_version != LAYOUT_VERSION || state.active_slot >= SLOT_COUNT {
            bail!("XDP control map has an incompatible layout");
        }
        self.reconcile_links()
    }

    pub fn cleanup(mut self) -> Result<()> {
        let pin_path = self.config.pin_path.clone();
        for (_, link) in std::mem::take(&mut self.links) {
            drop(link.unpin().context("unpin XDP link")?);
        }
        drop(self);
        remove_map_pins(&pin_path)
    }

    pub fn cleanup_pinned(config: &XdpConfig) -> Result<()> {
        validate_pinned_layout(config)?;
        if link_dir(config).exists() {
            for entry in fs::read_dir(link_dir(config))? {
                let path = entry?.path();
                if path.is_file() {
                    drop(PinnedLink::from_pin(&path)?.unpin()?);
                }
            }
        }
        remove_map_pins(&config.pin_path)
    }

    fn reconcile_links(&mut self) -> Result<()> {
        let missing: Vec<_> = self
            .interfaces
            .iter()
            .filter(|(ifindex, _)| !self.links.contains_key(ifindex))
            .map(|(ifindex, name)| (*ifindex, name.clone()))
            .collect();
        let mut attached = Vec::new();
        for (ifindex, name) in missing {
            let result = self.attach(&name, ifindex);
            if let Err(error) = result {
                for ifindex in attached {
                    if let Some(link) = self.links.remove(&ifindex)
                        && let Err(cleanup) = link.unpin()
                    {
                        log::error!("failed to roll back XDP link {ifindex}: {cleanup}");
                    }
                }
                return Err(error)
                    .with_context(|| format!("attach XDP to {name} (ifindex {ifindex})"));
            }
            attached.push(ifindex);
        }
        Ok(())
    }

    fn attach(&mut self, name: &str, ifindex: u32) -> Result<()> {
        let modes: &[XdpMode] = match self.config.mode {
            ConfigMode::Auto => &[XdpMode::Driver, XdpMode::Skb],
            ConfigMode::Native => &[XdpMode::Driver],
            ConfigMode::Generic => &[XdpMode::Skb],
        };
        let mut last = None;
        for (position, mode) in modes.iter().copied().enumerate() {
            let program: &mut Xdp = self
                ._ebpf
                .program_mut(PROGRAM)
                .context("XDP object has no cidrwall program")?
                .try_into()?;
            match program.attach_to_if_index(ifindex, mode) {
                Ok(id) => {
                    let link = program.take_link(id)?;
                    let fd_link: FdLink = link.try_into().map_err(|_| {
                        anyhow!(
                            "kernel used legacy XDP attachment, which cannot be pinned persistently"
                        )
                    })?;
                    let pinned = fd_link.pin(link_path(&self.config, ifindex))?;
                    self.links.insert(ifindex, pinned);
                    log::info!("attached XDP: interface={name} ifindex={ifindex} mode={mode:?}");
                    return Ok(());
                }
                Err(error) if position + 1 < modes.len() && unsupported_native(&error) => {
                    log::warn!("native XDP unsupported on {name}; retrying generic mode: {error}");
                    last = Some(error);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(last.context("no XDP attachment mode succeeded")?.into())
    }

    fn clear_slot(&mut self, slot: u32) -> Result<()> {
        let v4_keys: Vec<_> = self.v4_mut(slot).keys().collect::<Result<_, _>>()?;
        for key in v4_keys {
            self.v4_mut(slot).remove(&key)?;
        }
        let v6_keys: Vec<_> = self.v6_mut(slot).keys().collect::<Result<_, _>>()?;
        for key in v6_keys {
            self.v6_mut(slot).remove(&key)?;
        }
        Ok(())
    }

    fn v4_mut(&mut self, slot: u32) -> &mut V4Trie {
        if slot == 0 {
            &mut self.ipv4_a
        } else {
            &mut self.ipv4_b
        }
    }

    fn v6_mut(&mut self, slot: u32) -> &mut V6Trie {
        if slot == 0 {
            &mut self.ipv6_a
        } else {
            &mut self.ipv6_b
        }
    }
}

fn take_v4(ebpf: &mut Ebpf, name: &str) -> Result<V4Trie> {
    Ok(ebpf
        .take_map(name)
        .with_context(|| format!("XDP object has no {name} map"))?
        .try_into()?)
}

fn take_v6(ebpf: &mut Ebpf, name: &str) -> Result<V6Trie> {
    Ok(ebpf
        .take_map(name)
        .with_context(|| format!("XDP object has no {name} map"))?
        .try_into()?)
}

fn resolve_interfaces(names: BTreeSet<String>) -> Result<BTreeMap<u32, String>> {
    let mut interfaces = BTreeMap::new();
    for name in names {
        if name.contains('/') || name == "." || name == ".." {
            bail!("invalid interface name {name:?}");
        }
        let path = Path::new("/sys/class/net").join(&name).join("ifindex");
        let ifindex: u32 = fs::read_to_string(&path)
            .with_context(|| format!("XDP interface {name:?} does not exist"))?
            .trim()
            .parse()
            .with_context(|| format!("read interface index from {}", path.display()))?;
        if interfaces.insert(ifindex, name.clone()).is_some() {
            bail!("multiple XDP interfaces resolved to ifindex {ifindex}");
        }
    }
    Ok(interfaces)
}

fn open_owned_links(
    config: &XdpConfig,
    desired: BTreeSet<u32>,
) -> Result<BTreeMap<u32, PinnedLink>> {
    let mut links = BTreeMap::new();
    for entry in fs::read_dir(link_dir(config))? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Ok(ifindex) = name.parse::<u32>() else {
            continue;
        };
        let link = PinnedLink::from_pin(&path)
            .with_context(|| format!("open owned XDP link {}", path.display()))?;
        if desired.contains(&ifindex) {
            links.insert(ifindex, link);
        } else {
            drop(
                link.unpin()
                    .with_context(|| format!("remove obsolete XDP link {}", path.display()))?,
            );
        }
    }
    Ok(links)
}

fn unsupported_native(error: &aya::programs::ProgramError) -> bool {
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if let Some(io) = source.downcast_ref::<std::io::Error>() {
            return matches!(io.raw_os_error(), Some(22 | 45 | 95));
        }
        let Some(next) = source.source() else {
            return false;
        };
        source = next;
    }
}

fn validate_pinned_layout(config: &XdpConfig) -> Result<()> {
    let path = config.pin_path.join(CONTROL);
    if !path.exists() {
        bail!(
            "no cidrwall XDP state exists at {}",
            config.pin_path.display()
        );
    }
    let map = MapData::from_pin(&path)?;
    let control = Array::<_, Control>::try_from(aya::maps::Map::Array(map))?;
    let state = control.get(&0, 0)?;
    if state.layout_version != LAYOUT_VERSION || state.active_slot >= SLOT_COUNT {
        bail!(
            "refusing to clean an incompatible XDP layout at {}",
            config.pin_path.display()
        );
    }
    Ok(())
}

fn remove_map_pins(pin_path: &Path) -> Result<()> {
    for name in MAP_NAMES {
        let path = pin_path.join(name);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("remove XDP map pin {}", path.display()))?;
        }
    }
    let links = pin_path.join("links");
    if links.exists() {
        fs::remove_dir(&links)
            .with_context(|| format!("remove XDP link directory {}", links.display()))?;
    }
    if pin_path.exists() {
        fs::remove_dir(pin_path)
            .with_context(|| format!("remove XDP pin directory {}", pin_path.display()))?;
    }
    Ok(())
}

fn link_dir(config: &XdpConfig) -> PathBuf {
    config.pin_path.join("links")
}

fn link_path(config: &XdpConfig, ifindex: u32) -> PathBuf {
    link_dir(config).join(ifindex.to_string())
}
