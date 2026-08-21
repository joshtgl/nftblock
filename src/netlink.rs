use crate::{
    blocklist::{AddressInterval, StreamStats},
    config::{Config, Direction},
    rules::RenderedRule,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[cfg(feature = "native-netlink")]
#[allow(unsafe_code)]
mod ffi;

const LAYOUT_MARKER: &str = "__nftblock_layout_v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectionGeneration {
    pub direction: Direction,
    pub ipv4_set: String,
    pub ipv6_set: String,
    pub ipv4_boundaries: u64,
    pub ipv6_boundaries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGenerations {
    pub inbound: DirectionGeneration,
    pub outbound: DirectionGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutStatus {
    Absent,
    Current,
    Incompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    InboundDamaged,
    OutboundDamaged,
    LayoutDamaged,
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("netlink transaction failed: {0}")]
    Netlink(#[from] std::io::Error),
    #[error("native netlink support was disabled at build time")]
    Disabled,
    #[error("flowtable offload uses protected interface(s): {0:?}")]
    FlowtableBypass(BTreeSet<String>),
    #[error("invalid kernel object name: {0}")]
    InvalidName(String),
}

pub trait Backend {
    fn layout_status(&mut self, config: &Config) -> Result<LayoutStatus, BackendError>;
    fn bootstrap(&mut self, config: &Config, rules: &[RenderedRule]) -> Result<(), BackendError>;
    fn begin_stage(
        &mut self,
        config: &Config,
        direction: Direction,
    ) -> Result<DirectionGeneration, BackendError>;
    fn populate(
        &mut self,
        config: &Config,
        stage: &DirectionGeneration,
        intervals: &[AddressInterval],
    ) -> Result<(), BackendError>;
    fn activate_initial(
        &mut self,
        config: &Config,
        rules: &[RenderedRule],
        active: &ActiveGenerations,
    ) -> Result<(), BackendError>;
    fn activate_direction(
        &mut self,
        config: &Config,
        direction: Direction,
        generation: &DirectionGeneration,
    ) -> Result<(), BackendError>;
    fn discard(&mut self, config: &Config, stage: &DirectionGeneration)
    -> Result<(), BackendError>;
    fn cleanup_obsolete(
        &mut self,
        config: &Config,
        active: &ActiveGenerations,
    ) -> Result<(), BackendError>;
    fn health(
        &mut self,
        config: &Config,
        active: &ActiveGenerations,
    ) -> Result<Health, BackendError>;
    fn repair_rules(
        &mut self,
        config: &Config,
        rules: &[RenderedRule],
        active: &ActiveGenerations,
    ) -> Result<(), BackendError>;
    fn flowtable_conflicts(
        &mut self,
        protected: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, BackendError>;
}

pub fn apply_stats(stage: &mut DirectionGeneration, stats: StreamStats) {
    stage.ipv4_boundaries = stats.ipv4_boundaries;
    stage.ipv6_boundaries = stats.ipv6_boundaries;
}

#[cfg(feature = "native-netlink")]
pub use native::NftnlBackend;

#[cfg(not(feature = "native-netlink"))]
#[derive(Default)]
pub struct NftnlBackend;

#[cfg(not(feature = "native-netlink"))]
impl NftnlBackend {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "native-netlink"))]
impl Backend for NftnlBackend {
    fn layout_status(&mut self, _: &Config) -> Result<LayoutStatus, BackendError> {
        Err(BackendError::Disabled)
    }
    fn bootstrap(&mut self, _: &Config, _: &[RenderedRule]) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn begin_stage(
        &mut self,
        _: &Config,
        _: Direction,
    ) -> Result<DirectionGeneration, BackendError> {
        Err(BackendError::Disabled)
    }
    fn populate(
        &mut self,
        _: &Config,
        _: &DirectionGeneration,
        _: &[AddressInterval],
    ) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn activate_initial(
        &mut self,
        _: &Config,
        _: &[RenderedRule],
        _: &ActiveGenerations,
    ) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn activate_direction(
        &mut self,
        _: &Config,
        _: Direction,
        _: &DirectionGeneration,
    ) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn discard(&mut self, _: &Config, _: &DirectionGeneration) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn cleanup_obsolete(&mut self, _: &Config, _: &ActiveGenerations) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn health(&mut self, _: &Config, _: &ActiveGenerations) -> Result<Health, BackendError> {
        Err(BackendError::Disabled)
    }
    fn repair_rules(
        &mut self,
        _: &Config,
        _: &[RenderedRule],
        _: &ActiveGenerations,
    ) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn flowtable_conflicts(
        &mut self,
        _: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, BackendError> {
        Err(BackendError::Disabled)
    }
}

#[cfg(feature = "native-netlink")]
mod native {
    use super::ffi::{
        AlignedNetlinkBuffer, ExistingElements, ExistingSetMessage, Flowtable, IntervalSet,
        NamedLookup, NetlinkRequest, RuleFlush, SetInfo, TableInfo,
    };
    use super::*;
    use crate::zones::Chain as RuleChain;
    use nftnl::{
        Batch, Chain, FinalizedBatch, Hook, MsgType, ProtoFamily, Rule, Table, nft_expr,
        nftnl_sys::libc, set::SetKey,
    };
    use std::{
        ffi::{CStr, CString},
        io,
        net::{Ipv4Addr, Ipv6Addr},
    };

    const IN_DISPATCH: &CStr = c"inbound_dispatch";
    const OUT_DISPATCH: &CStr = c"outbound_dispatch";

    pub struct NftnlBackend {
        next_generation: u64,
    }
    impl NftnlBackend {
        pub fn new() -> Self {
            Self { next_generation: 1 }
        }
    }
    impl Default for NftnlBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Backend for NftnlBackend {
        fn layout_status(&mut self, config: &Config) -> Result<LayoutStatus, BackendError> {
            let tables = table_names()?;
            if !tables.contains(&config.nftables.table) {
                return Ok(LayoutStatus::Absent);
            }
            let sets = set_inventory(&config.nftables.table)?;
            self.observe_generations(sets.keys());
            Ok(if sets.contains_key(LAYOUT_MARKER) {
                LayoutStatus::Current
            } else {
                LayoutStatus::Incompatible
            })
        }

        fn bootstrap(
            &mut self,
            config: &Config,
            rules: &[RenderedRule],
        ) -> Result<(), BackendError> {
            let table_name = cstring(&config.nftables.table)?;
            let table = Table::new(&table_name, ProtoFamily::Inet);
            let (input, forward, output, inbound, outbound) = make_chains(config, &table);
            let marker = interval_set::<Ipv4Addr>(c"__nftblock_layout_v2", 90, &table);
            let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
            batch.add(&table, MsgType::Add);
            add_chain_set(&mut batch, (&input, &forward, &output, &inbound, &outbound));
            batch.add(marker.as_set(), MsgType::Add);
            add_base_rules(&mut batch, &input, &forward, &output, rules)?;
            send_and_process(&batch.finalize()).map_err(Into::into)
        }

        fn begin_stage(
            &mut self,
            config: &Config,
            direction: Direction,
        ) -> Result<DirectionGeneration, BackendError> {
            let generation = self.next_generation;
            self.next_generation = self
                .next_generation
                .checked_add(1)
                .ok_or_else(|| BackendError::InvalidName("generation counter exhausted".into()))?;
            let prefix = match direction {
                Direction::Inbound => "in",
                Direction::Outbound => "out",
            };
            let ipv4_set = format!("{prefix}_v4_g{generation:016x}");
            let ipv6_set = format!("{prefix}_v6_g{generation:016x}");
            let table_name = cstring(&config.nftables.table)?;
            let table = Table::new(&table_name, ProtoFamily::Inet);
            let v4_name = cstring(&ipv4_set)?;
            let v6_name = cstring(&ipv6_set)?;
            let v4 = interval_set::<Ipv4Addr>(&v4_name, 1, &table);
            let v6 = interval_set::<Ipv6Addr>(&v6_name, 2, &table);
            let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
            batch.add(v4.as_set(), MsgType::Add);
            batch.add(v6.as_set(), MsgType::Add);
            send_and_process(&batch.finalize())?;
            Ok(DirectionGeneration {
                direction,
                ipv4_set,
                ipv6_set,
                ipv4_boundaries: 0,
                ipv6_boundaries: 0,
            })
        }

        fn populate(
            &mut self,
            config: &Config,
            stage: &DirectionGeneration,
            intervals: &[AddressInterval],
        ) -> Result<(), BackendError> {
            if intervals.is_empty() {
                return Ok(());
            }
            let table_name = cstring(&config.nftables.table)?;
            let table = Table::new(&table_name, ProtoFamily::Inet);
            let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
            match intervals[0] {
                AddressInterval::V4 { .. } => {
                    let name = cstring(&stage.ipv4_set)?;
                    let mut set = IntervalSet::<Ipv4Addr>::existing(&name, &table);
                    for interval in intervals {
                        let AddressInterval::V4 { first, after_last } = interval else {
                            return Err(BackendError::InvalidName(
                                "mixed-family population chunk".into(),
                            ));
                        };
                        set.add_range(first, after_last.as_ref())?;
                    }
                    batch.add_iter(
                        set.as_set().elems_iter().map(ExistingElements::new),
                        MsgType::Add,
                    );
                }
                AddressInterval::V6 { .. } => {
                    let name = cstring(&stage.ipv6_set)?;
                    let mut set = IntervalSet::<Ipv6Addr>::existing(&name, &table);
                    for interval in intervals {
                        let AddressInterval::V6 { first, after_last } = interval else {
                            return Err(BackendError::InvalidName(
                                "mixed-family population chunk".into(),
                            ));
                        };
                        set.add_range(first, after_last.as_ref())?;
                    }
                    batch.add_iter(
                        set.as_set().elems_iter().map(ExistingElements::new),
                        MsgType::Add,
                    );
                }
            }
            send_and_process(&batch.finalize()).map_err(Into::into)
        }

        fn activate_initial(
            &mut self,
            config: &Config,
            rules: &[RenderedRule],
            active: &ActiveGenerations,
        ) -> Result<(), BackendError> {
            replace_rules(config, rules, active).map_err(Into::into)
        }

        fn activate_direction(
            &mut self,
            config: &Config,
            direction: Direction,
            generation: &DirectionGeneration,
        ) -> Result<(), BackendError> {
            replace_dispatch(config, direction, generation).map_err(Into::into)
        }

        fn discard(
            &mut self,
            config: &Config,
            stage: &DirectionGeneration,
        ) -> Result<(), BackendError> {
            delete_sets(config, [&stage.ipv4_set, &stage.ipv6_set]).map_err(Into::into)
        }

        fn cleanup_obsolete(
            &mut self,
            config: &Config,
            active: &ActiveGenerations,
        ) -> Result<(), BackendError> {
            let keep: BTreeSet<&str> = [
                active.inbound.ipv4_set.as_str(),
                active.inbound.ipv6_set.as_str(),
                active.outbound.ipv4_set.as_str(),
                active.outbound.ipv6_set.as_str(),
            ]
            .into_iter()
            .collect();
            let sets = set_inventory(&config.nftables.table)?;
            let obsolete: Vec<String> = sets
                .keys()
                .filter(|name| is_generation(name) && !keep.contains(name.as_str()))
                .cloned()
                .collect();
            delete_sets(config, obsolete.iter()).map_err(Into::into)
        }

        fn health(
            &mut self,
            config: &Config,
            active: &ActiveGenerations,
        ) -> Result<Health, BackendError> {
            let sets = set_inventory(&config.nftables.table)?;
            if !sets.contains_key(LAYOUT_MARKER) {
                return Ok(Health::LayoutDamaged);
            }
            let damaged = |value: &DirectionGeneration| {
                sets.get(&value.ipv4_set).copied().flatten().map(u64::from)
                    != Some(value.ipv4_boundaries)
                    || sets.get(&value.ipv6_set).copied().flatten().map(u64::from)
                        != Some(value.ipv6_boundaries)
            };
            match (damaged(&active.inbound), damaged(&active.outbound)) {
                (false, false) => Ok(Health::Healthy),
                (true, false) => Ok(Health::InboundDamaged),
                (false, true) => Ok(Health::OutboundDamaged),
                (true, true) => Ok(Health::LayoutDamaged),
            }
        }

        fn repair_rules(
            &mut self,
            config: &Config,
            rules: &[RenderedRule],
            active: &ActiveGenerations,
        ) -> Result<(), BackendError> {
            replace_rules(config, rules, active).map_err(Into::into)
        }

        fn flowtable_conflicts(
            &mut self,
            protected: &BTreeSet<String>,
        ) -> Result<BTreeSet<String>, BackendError> {
            flowtable_conflicts(protected).map_err(Into::into)
        }
    }

    impl NftnlBackend {
        fn observe_generations<'a>(&mut self, names: impl Iterator<Item = &'a String>) {
            for name in names {
                if let Some(hex) = name.rsplit_once("_g").map(|(_, value)| value)
                    && let Ok(value) = u64::from_str_radix(hex, 16)
                {
                    self.next_generation = self.next_generation.max(value.saturating_add(1));
                }
            }
        }
    }

    fn cstring(value: &str) -> Result<CString, BackendError> {
        CString::new(value).map_err(|_| BackendError::InvalidName(value.into()))
    }

    fn interval_set<'a, T: SetKey>(name: &CStr, id: u32, table: &'a Table) -> IntervalSet<'a, T> {
        IntervalSet::new(name, id, table)
    }

    fn make_chains<'a>(
        config: &Config,
        table: &'a Table,
    ) -> (Chain<'a>, Chain<'a>, Chain<'a>, Chain<'a>, Chain<'a>) {
        let mut input = Chain::new(c"input", table);
        input.set_hook(Hook::In, config.nftables.priority);
        let mut forward = Chain::new(c"forward", table);
        forward.set_hook(Hook::Forward, config.nftables.priority);
        let mut output = Chain::new(c"output", table);
        output.set_hook(Hook::Out, config.nftables.priority);
        let inbound = Chain::new(IN_DISPATCH, table);
        let outbound = Chain::new(OUT_DISPATCH, table);
        (input, forward, output, inbound, outbound)
    }

    fn add_chain_set(
        batch: &mut Batch,
        chains: (&Chain<'_>, &Chain<'_>, &Chain<'_>, &Chain<'_>, &Chain<'_>),
    ) {
        for chain in [chains.0, chains.1, chains.2, chains.3, chains.4] {
            batch.add(chain, MsgType::Add);
        }
    }

    fn base_chain<'a>(
        spec: &RenderedRule,
        input: &'a Chain<'a>,
        forward: &'a Chain<'a>,
        output: &'a Chain<'a>,
    ) -> &'a Chain<'a> {
        match spec.chain {
            RuleChain::Input => input,
            RuleChain::Forward => forward,
            RuleChain::Output => output,
        }
    }

    fn add_base_rules(
        batch: &mut Batch,
        input: &Chain<'_>,
        forward: &Chain<'_>,
        output: &Chain<'_>,
        rules: &[RenderedRule],
    ) -> Result<(), BackendError> {
        use nftnl::expr::{InterfaceName, Verdict};
        for spec in rules {
            let chain = base_chain(spec, input, forward, output);
            let mut rule = Rule::new(chain);
            if let Some(name) = &spec.ingress {
                rule.add_expr(&nft_expr!(meta iifname));
                rule.add_expr(&nft_expr!(cmp == InterfaceName::Exact(cstring(name)?)));
            }
            if let Some(name) = &spec.egress {
                rule.add_expr(&nft_expr!(meta oifname));
                rule.add_expr(&nft_expr!(cmp == InterfaceName::Exact(cstring(name)?)));
            }
            let target = match spec.direction {
                Direction::Inbound => IN_DISPATCH,
                Direction::Outbound => OUT_DISPATCH,
            };
            rule.add_expr(&Verdict::Jump {
                chain: target.to_owned(),
            });
            batch.add(&rule, MsgType::Add);
        }
        Ok(())
    }

    fn add_dispatch_rules(
        batch: &mut Batch,
        chain: &Chain<'_>,
        generation: &DirectionGeneration,
        direction: Direction,
    ) -> Result<(), BackendError> {
        let v4_name = cstring(&generation.ipv4_set)?;
        let v6_name = cstring(&generation.ipv6_set)?;
        add_lookup_rule(batch, chain, direction, &v4_name, libc::NFPROTO_IPV4 as u8);
        add_lookup_rule(batch, chain, direction, &v6_name, libc::NFPROTO_IPV6 as u8);
        Ok(())
    }

    fn add_lookup_rule(
        batch: &mut Batch,
        chain: &Chain<'_>,
        direction: Direction,
        set_name: &CStr,
        family: u8,
    ) {
        use nftnl::expr::{Ipv4HeaderField, Ipv6HeaderField, NetworkHeaderField, Payload};
        let mut rule = Rule::new(chain);
        rule.add_expr(&nft_expr!(meta nfproto));
        rule.add_expr(&nft_expr!(cmp == family));
        let field = match (family as i32, direction) {
            (libc::NFPROTO_IPV4, Direction::Inbound) => {
                Payload::Network(NetworkHeaderField::Ipv4(Ipv4HeaderField::Saddr))
            }
            (libc::NFPROTO_IPV4, Direction::Outbound) => {
                Payload::Network(NetworkHeaderField::Ipv4(Ipv4HeaderField::Daddr))
            }
            (_, Direction::Inbound) => {
                Payload::Network(NetworkHeaderField::Ipv6(Ipv6HeaderField::Saddr))
            }
            (_, Direction::Outbound) => {
                Payload::Network(NetworkHeaderField::Ipv6(Ipv6HeaderField::Daddr))
            }
        };
        rule.add_expr(&field);
        rule.add_expr(&NamedLookup::new(set_name));
        rule.add_expr(&nft_expr!(verdict drop));
        batch.add(&rule, MsgType::Add);
    }

    fn replace_rules(
        config: &Config,
        rules: &[RenderedRule],
        active: &ActiveGenerations,
    ) -> io::Result<()> {
        let table_name = CString::new(config.nftables.table.as_str())
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let table = Table::new(&table_name, ProtoFamily::Inet);
        let (input, forward, output, inbound, outbound) = make_chains(config, &table);
        let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
        add_chain_set(&mut batch, (&input, &forward, &output, &inbound, &outbound));
        for chain in [&input, &forward, &output, &inbound, &outbound] {
            batch.add(&RuleFlush::new(chain), MsgType::Del);
        }
        add_base_rules(&mut batch, &input, &forward, &output, rules).map_err(io::Error::other)?;
        add_dispatch_rules(&mut batch, &inbound, &active.inbound, Direction::Inbound)
            .map_err(io::Error::other)?;
        add_dispatch_rules(&mut batch, &outbound, &active.outbound, Direction::Outbound)
            .map_err(io::Error::other)?;
        send_and_process(&batch.finalize())
    }

    fn replace_dispatch(
        config: &Config,
        direction: Direction,
        generation: &DirectionGeneration,
    ) -> io::Result<()> {
        let table_name = CString::new(config.nftables.table.as_str())
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let table = Table::new(&table_name, ProtoFamily::Inet);
        let name = match direction {
            Direction::Inbound => IN_DISPATCH,
            Direction::Outbound => OUT_DISPATCH,
        };
        let chain = Chain::new(name, &table);
        let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
        batch.add(&chain, MsgType::Add);
        batch.add(&RuleFlush::new(&chain), MsgType::Del);
        add_dispatch_rules(&mut batch, &chain, generation, direction).map_err(io::Error::other)?;
        send_and_process(&batch.finalize())
    }

    fn delete_sets<'a>(
        config: &Config,
        names: impl IntoIterator<Item = &'a String>,
    ) -> io::Result<()> {
        let table_name = CString::new(config.nftables.table.as_str())
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let table = Table::new(&table_name, ProtoFamily::Inet);
        let names: Vec<CString> = names
            .into_iter()
            .map(|name| CString::new(name.as_str()))
            .collect::<Result<_, _>>()
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        if names.is_empty() {
            return Ok(());
        }
        let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
        for name in &names {
            if name.to_bytes().windows(4).any(|part| part == b"_v6_") {
                let set = IntervalSet::<Ipv6Addr>::existing(name, &table);
                batch.add(&ExistingSetMessage::new(set.as_set()), MsgType::Del);
            } else {
                let set = IntervalSet::<Ipv4Addr>::existing(name, &table);
                batch.add(&ExistingSetMessage::new(set.as_set()), MsgType::Del);
            }
        }
        send_and_process(&batch.finalize())
    }

    fn is_generation(name: &str) -> bool {
        ["in_v4_g", "in_v6_g", "out_v4_g", "out_v6_g"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }

    fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
        let portid = socket.portid();
        socket.send_all(batch)?;
        let mut buffer = AlignedNetlinkBuffer::new(nftnl::nft_nlmsg_maxsize() as usize);
        let mut seqs = batch.sequence_numbers();
        while !seqs.is_empty() {
            for message in socket.recv(buffer.as_bytes_mut())? {
                let message = message?;
                let seq = seqs.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected netlink ACK")
                })?;
                mnl::cb_run(message, seq, portid)?;
            }
        }
        Ok(())
    }

    fn table_names() -> io::Result<BTreeSet<String>> {
        fn collect(
            message: &libc::nlmsghdr,
            state: &mut (BTreeSet<String>, Option<io::Error>),
        ) -> libc::c_int {
            match TableInfo::parse(message).and_then(|value| value.name()) {
                Ok(name) => {
                    state.0.insert(name);
                    mnl::mnl_sys::MNL_CB_OK
                }
                Err(error) => {
                    state.1 = Some(error);
                    mnl::mnl_sys::MNL_CB_ERROR
                }
            }
        }
        let request = NetlinkRequest::table_dump(1)?;
        dump(request, collect, (BTreeSet::new(), None)).map(|state| state.0)
    }

    fn set_inventory(table: &str) -> io::Result<BTreeMap<String, Option<u32>>> {
        fn collect(
            message: &libc::nlmsghdr,
            state: &mut (String, BTreeMap<String, Option<u32>>, Option<io::Error>),
        ) -> libc::c_int {
            let count = SetInfo::count(message);
            match SetInfo::parse(message)
                .and_then(|value| Ok((value.table()?, value.name()?, count)))
            {
                Ok((table, name, count)) => {
                    if table == state.0 {
                        state.1.insert(name, count);
                    }
                    mnl::mnl_sys::MNL_CB_OK
                }
                Err(error) => {
                    state.2 = Some(error);
                    mnl::mnl_sys::MNL_CB_ERROR
                }
            }
        }
        let request = NetlinkRequest::set_dump(1)?;
        dump(request, collect, (table.to_owned(), BTreeMap::new(), None)).map(|state| state.1)
    }

    trait DumpState {
        fn take_error(&mut self) -> Option<io::Error>;
    }
    impl DumpState for (BTreeSet<String>, Option<io::Error>) {
        fn take_error(&mut self) -> Option<io::Error> {
            self.1.take()
        }
    }
    impl DumpState for (String, BTreeMap<String, Option<u32>>, Option<io::Error>) {
        fn take_error(&mut self) -> Option<io::Error> {
            self.2.take()
        }
    }
    fn dump<S: DumpState>(
        request: NetlinkRequest,
        callback: fn(&libc::nlmsghdr, &mut S) -> libc::c_int,
        mut state: S,
    ) -> io::Result<S> {
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
        let portid = socket.portid();
        socket.send(request.as_bytes())?;
        let mut buffer = AlignedNetlinkBuffer::new(nftnl::nft_nlmsg_maxsize() as usize);
        loop {
            let len = socket.recv_raw(buffer.as_bytes_mut())?;
            let result = mnl::cb_run2(buffer.prefix(len)?, 1, portid, callback, &mut state);
            if let Some(error) = state.take_error() {
                return Err(error);
            }
            if matches!(result?, mnl::CbResult::Stop) {
                return Ok(state);
            }
        }
    }

    fn flowtable_conflicts(protected: &BTreeSet<String>) -> io::Result<BTreeSet<String>> {
        #[derive(Default)]
        struct State {
            devices: BTreeSet<String>,
            error: Option<io::Error>,
        }
        fn collect(message: &libc::nlmsghdr, state: &mut State) -> libc::c_int {
            match Flowtable::parse(message).and_then(|value| value.device_names()) {
                Ok(values) => {
                    state.devices.extend(values);
                    mnl::mnl_sys::MNL_CB_OK
                }
                Err(error) => {
                    state.error = Some(error);
                    mnl::mnl_sys::MNL_CB_ERROR
                }
            }
        }
        let request = NetlinkRequest::flowtable_dump(1)?;
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
        let portid = socket.portid();
        socket.send(request.as_bytes())?;
        let mut buffer = AlignedNetlinkBuffer::new(nftnl::nft_nlmsg_maxsize() as usize);
        let mut state = State::default();
        loop {
            let len = socket.recv_raw(buffer.as_bytes_mut())?;
            let result = mnl::cb_run2(buffer.prefix(len)?, 1, portid, collect, &mut state);
            if let Some(error) = state.error.take() {
                return Err(error);
            }
            if matches!(result?, mnl::CbResult::Stop) {
                break;
            }
        }
        Ok(state.devices.intersection(protected).cloned().collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{BufReader, BufWriter, Write};
        #[test]
        fn bounded_chunk_serialization_spans_pages() {
            let table = Table::new(c"page-test", ProtoFamily::Inet);
            let mut set = interval_set::<Ipv4Addr>(c"addresses", 1, &table);
            for value in 0..50_000u32 {
                set.add_range(
                    &Ipv4Addr::from(value * 2),
                    Some(&Ipv4Addr::from(value * 2 + 1)),
                )
                .unwrap();
            }
            let mut batch = Batch::with_page_size(65_536);
            batch.add_iter(
                set.as_set().elems_iter().map(ExistingElements::new),
                MsgType::Add,
            );
            assert!(batch.finalize().iter().count() > 1);
        }

        /// Run with:
        /// cargo test --release netlink::native::tests::streams_4_2m_entries_under_256_mib -- --ignored --exact --nocapture
        #[test]
        #[ignore = "release-mode 4.2-million-entry RSS validation"]
        fn streams_4_2m_entries_under_256_mib() {
            const ENTRY_COUNT: u32 = 4_228_762;
            const BOUNDARY_LIMIT: usize = 100_000;
            let file = tempfile::NamedTempFile::new().unwrap();
            {
                let mut writer = BufWriter::new(file.as_file());
                for index in 0..ENTRY_COUNT {
                    writeln!(writer, "{}/32", Ipv4Addr::from(index * 2)).unwrap();
                }
                writer.flush().unwrap();
            }
            let reader = BufReader::new(std::fs::File::open(file.path()).unwrap());
            let table = Table::new(c"rss-test", ProtoFamily::Inet);
            let mut chunks = 0u64;
            let stats = crate::blocklist::stream_chunks(reader, BOUNDARY_LIMIT, |intervals| {
                let mut set = interval_set::<Ipv4Addr>(c"addresses", 1, &table);
                let mut boundaries = 0usize;
                for interval in intervals {
                    let AddressInterval::V4 { first, after_last } = interval else {
                        unreachable!()
                    };
                    set.add_range(first, after_last.as_ref())?;
                    boundaries += interval.boundary_elements();
                }
                assert!(boundaries <= BOUNDARY_LIMIT);
                let mut batch = Batch::with_page_size(256 * 1024);
                batch.add_iter(
                    set.as_set().elems_iter().map(ExistingElements::new),
                    MsgType::Add,
                );
                let serialized: usize = batch.finalize().iter().map(<[u8]>::len).sum();
                assert!(serialized > 0);
                chunks += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(stats.cidrs, u64::from(ENTRY_COUNT));
            assert_eq!(stats.ipv4_boundaries, u64::from(ENTRY_COUNT) * 2);
            assert!(chunks > 1);
            #[cfg(target_os = "linux")]
            {
                const BUDGET_KIB: u64 = 256 * 1024;
                let status = std::fs::read_to_string("/proc/self/status").unwrap();
                let peak_kib = status
                    .lines()
                    .find_map(|line| line.strip_prefix("VmHWM:"))
                    .and_then(|value| value.split_whitespace().next())
                    .unwrap()
                    .parse::<u64>()
                    .unwrap();
                eprintln!("nftblock scale-test peak RSS: {peak_kib} KiB");
                assert!(
                    peak_kib < BUDGET_KIB,
                    "peak RSS {peak_kib} KiB exceeded 256 MiB"
                );
            }
        }
    }
}

#[cfg(test)]
pub mod test_backend {
    use super::*;
    #[derive(Default)]
    pub struct MemoryBackend {
        pub layout: Option<LayoutStatus>,
        pub chunks: Vec<usize>,
        pub active: Option<ActiveGenerations>,
        pub fail_next: bool,
        pub generation: u64,
    }
    impl Backend for MemoryBackend {
        fn layout_status(&mut self, _: &Config) -> Result<LayoutStatus, BackendError> {
            Ok(self.layout.unwrap_or(LayoutStatus::Absent))
        }
        fn bootstrap(&mut self, _: &Config, _: &[RenderedRule]) -> Result<(), BackendError> {
            self.layout = Some(LayoutStatus::Current);
            Ok(())
        }
        fn begin_stage(
            &mut self,
            _: &Config,
            direction: Direction,
        ) -> Result<DirectionGeneration, BackendError> {
            self.generation += 1;
            Ok(DirectionGeneration {
                direction,
                ipv4_set: format!("v4-{}", self.generation),
                ipv6_set: format!("v6-{}", self.generation),
                ipv4_boundaries: 0,
                ipv6_boundaries: 0,
            })
        }
        fn populate(
            &mut self,
            _: &Config,
            _: &DirectionGeneration,
            intervals: &[AddressInterval],
        ) -> Result<(), BackendError> {
            self.chunks
                .push(intervals.iter().map(|v| v.boundary_elements()).sum());
            if std::mem::take(&mut self.fail_next) {
                return Err(std::io::Error::other("injected chunk error").into());
            }
            Ok(())
        }
        fn activate_initial(
            &mut self,
            _: &Config,
            _: &[RenderedRule],
            active: &ActiveGenerations,
        ) -> Result<(), BackendError> {
            if std::mem::take(&mut self.fail_next) {
                return Err(std::io::Error::other("injected activation error").into());
            }
            self.active = Some(active.clone());
            Ok(())
        }
        fn activate_direction(
            &mut self,
            _: &Config,
            direction: Direction,
            generation: &DirectionGeneration,
        ) -> Result<(), BackendError> {
            if std::mem::take(&mut self.fail_next) {
                return Err(std::io::Error::other("injected activation error").into());
            }
            let active = self.active.as_mut().unwrap();
            match direction {
                Direction::Inbound => active.inbound = generation.clone(),
                Direction::Outbound => active.outbound = generation.clone(),
            }
            Ok(())
        }
        fn discard(&mut self, _: &Config, _: &DirectionGeneration) -> Result<(), BackendError> {
            Ok(())
        }
        fn cleanup_obsolete(
            &mut self,
            _: &Config,
            _: &ActiveGenerations,
        ) -> Result<(), BackendError> {
            Ok(())
        }
        fn health(&mut self, _: &Config, _: &ActiveGenerations) -> Result<Health, BackendError> {
            Ok(Health::Healthy)
        }
        fn repair_rules(
            &mut self,
            _: &Config,
            _: &[RenderedRule],
            _: &ActiveGenerations,
        ) -> Result<(), BackendError> {
            Ok(())
        }
        fn flowtable_conflicts(
            &mut self,
            _: &BTreeSet<String>,
        ) -> Result<BTreeSet<String>, BackendError> {
            Ok(BTreeSet::new())
        }
    }
}
