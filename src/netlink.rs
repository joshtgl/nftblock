use crate::{blocklist::ParsedBlocklist, config::Config, rules::RenderedRule};
use std::collections::BTreeSet;
use thiserror::Error;

#[cfg(feature = "native-netlink")]
#[allow(unsafe_code)]
mod ffi;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub inbound: ParsedBlocklist,
    pub outbound: ParsedBlocklist,
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
    /// Replace the complete owned table in one kernel transaction.
    fn apply(
        &mut self,
        config: &Config,
        rules: &[RenderedRule],
        snapshot: &Snapshot,
    ) -> Result<(), BackendError>;
    /// Atomically flush and refill only one direction's IPv4/IPv6 sets.
    fn apply_direction(
        &mut self,
        config: &Config,
        rules: &[RenderedRule],
        direction: crate::config::Direction,
        snapshot: &Snapshot,
    ) -> Result<(), BackendError>;
    /// Return protected interfaces currently attached to any flowtable.
    fn flowtable_conflicts(
        &mut self,
        protected: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, BackendError>;
}

#[cfg(feature = "native-netlink")]
pub use native::NftnlBackend;

#[cfg(not(feature = "native-netlink"))]
pub struct NftnlBackend;

#[cfg(not(feature = "native-netlink"))]
impl NftnlBackend {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "native-netlink"))]
impl Default for NftnlBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "native-netlink"))]
impl Backend for NftnlBackend {
    fn apply(&mut self, _: &Config, _: &[RenderedRule], _: &Snapshot) -> Result<(), BackendError> {
        Err(BackendError::Disabled)
    }
    fn apply_direction(
        &mut self,
        _: &Config,
        _: &[RenderedRule],
        _: crate::config::Direction,
        _: &Snapshot,
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
    use super::ffi::{AlignedNetlinkBuffer, Flowtable, IntervalSet, NetlinkRequest, SetFlush};
    use super::*;
    use crate::{
        blocklist::{ipv4_intervals, ipv6_intervals},
        config::Direction,
        rules::AddressField,
        zones::Chain as RuleChain,
    };
    use nftnl::{
        Batch, Chain, FinalizedBatch, Hook, MsgType, ProtoFamily, Rule, Table, nft_expr,
        nftnl_sys::libc,
        set::{Set, SetKey},
    };
    use std::{
        ffi::{CStr, CString},
        io,
        net::{Ipv4Addr, Ipv6Addr},
    };

    const IN_V4: &CStr = c"inbound_v4";
    const IN_V6: &CStr = c"inbound_v6";
    const OUT_V4: &CStr = c"outbound_v4";
    const OUT_V6: &CStr = c"outbound_v6";

    pub struct NftnlBackend {
        table_known: bool,
    }
    impl NftnlBackend {
        pub fn new() -> Self {
            Self { table_known: true }
        }
    }
    impl Default for NftnlBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Backend for NftnlBackend {
        fn apply(
            &mut self,
            config: &Config,
            rules: &[RenderedRule],
            snapshot: &Snapshot,
        ) -> Result<(), BackendError> {
            let replace = self.table_known;
            match build_and_send(config, rules, snapshot, replace) {
                Ok(()) => {
                    self.table_known = true;
                    Ok(())
                }
                Err(error) if replace && error.raw_os_error() == Some(libc::ENOENT) => {
                    build_and_send(config, rules, snapshot, false)?;
                    self.table_known = true;
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        }

        fn flowtable_conflicts(
            &mut self,
            protected: &BTreeSet<String>,
        ) -> Result<BTreeSet<String>, BackendError> {
            flowtable_conflicts(protected).map_err(Into::into)
        }

        fn apply_direction(
            &mut self,
            config: &Config,
            rules: &[RenderedRule],
            direction: Direction,
            snapshot: &Snapshot,
        ) -> Result<(), BackendError> {
            match replace_direction(config, direction, snapshot) {
                Ok(()) => {
                    self.table_known = true;
                    Ok(())
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    build_and_send(config, rules, snapshot, false)?;
                    self.table_known = true;
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        }
    }

    fn replace_direction(
        config: &Config,
        direction: Direction,
        snapshot: &Snapshot,
    ) -> io::Result<()> {
        let table_name = CString::new(config.nftables.table.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "table name contains NUL"))?;
        let table = Table::new(&table_name, ProtoFamily::Inet);
        let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
        match direction {
            Direction::Inbound => {
                let mut v4 = interval_set::<Ipv4Addr>(IN_V4, 1, &table);
                let mut v6 = interval_set::<Ipv6Addr>(IN_V6, 2, &table);
                add_v4_intervals(&mut v4, &snapshot.inbound.ipv4)?;
                add_v6_intervals(&mut v6, &snapshot.inbound.ipv6)?;
                let flush_v4 = interval_set::<Ipv4Addr>(IN_V4, 1, &table);
                let flush_v6 = interval_set::<Ipv6Addr>(IN_V6, 2, &table);
                replace_set(&mut batch, &flush_v4, &v4);
                replace_set(&mut batch, &flush_v6, &v6);
            }
            Direction::Outbound => {
                let mut v4 = interval_set::<Ipv4Addr>(OUT_V4, 3, &table);
                let mut v6 = interval_set::<Ipv6Addr>(OUT_V6, 4, &table);
                add_v4_intervals(&mut v4, &snapshot.outbound.ipv4)?;
                add_v6_intervals(&mut v6, &snapshot.outbound.ipv6)?;
                let flush_v4 = interval_set::<Ipv4Addr>(OUT_V4, 3, &table);
                let flush_v6 = interval_set::<Ipv6Addr>(OUT_V6, 4, &table);
                replace_set(&mut batch, &flush_v4, &v4);
                replace_set(&mut batch, &flush_v6, &v6);
            }
        }
        send_and_process(&batch.finalize())
    }

    fn replace_set<T: SetKey>(
        batch: &mut Batch,
        empty_selector: &IntervalSet<'_, T>,
        populated: &IntervalSet<'_, T>,
    ) {
        batch.add(&SetFlush::new(empty_selector.as_set()), MsgType::Del);
        batch.add_iter(populated.as_set().elems_iter(), MsgType::Add);
    }

    fn build_and_send(
        config: &Config,
        rendered: &[RenderedRule],
        snapshot: &Snapshot,
        replace: bool,
    ) -> io::Result<()> {
        if !nftnl::batch_is_supported().map_err(io::Error::other)? {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kernel does not support nftables batches",
            ));
        }
        let table_name = CString::new(config.nftables.table.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "table name contains NUL"))?;
        let table = Table::new(&table_name, ProtoFamily::Inet);
        let mut batch = Batch::with_page_size(config.nftables.batch_page_bytes);
        if replace {
            batch.add(&table, MsgType::Del);
        }
        batch.add(&table, MsgType::Add);

        let mut input = Chain::new(c"input", &table);
        input.set_hook(Hook::In, config.nftables.priority);
        let mut forward = Chain::new(c"forward", &table);
        forward.set_hook(Hook::Forward, config.nftables.priority);
        let mut output = Chain::new(c"output", &table);
        output.set_hook(Hook::Out, config.nftables.priority);
        batch.add(&input, MsgType::Add);
        batch.add(&forward, MsgType::Add);
        batch.add(&output, MsgType::Add);

        let mut in_v4 = interval_set::<Ipv4Addr>(IN_V4, 1, &table);
        let mut in_v6 = interval_set::<Ipv6Addr>(IN_V6, 2, &table);
        let mut out_v4 = interval_set::<Ipv4Addr>(OUT_V4, 3, &table);
        let mut out_v6 = interval_set::<Ipv6Addr>(OUT_V6, 4, &table);
        add_v4_intervals(&mut in_v4, &snapshot.inbound.ipv4)?;
        add_v6_intervals(&mut in_v6, &snapshot.inbound.ipv6)?;
        add_v4_intervals(&mut out_v4, &snapshot.outbound.ipv4)?;
        add_v6_intervals(&mut out_v6, &snapshot.outbound.ipv6)?;
        add_set(&mut batch, &in_v4);
        add_set(&mut batch, &in_v6);
        add_set(&mut batch, &out_v4);
        add_set(&mut batch, &out_v6);

        for spec in rendered {
            let chain = match spec.chain {
                RuleChain::Input => &input,
                RuleChain::Forward => &forward,
                RuleChain::Output => &output,
            };
            match spec.direction {
                Direction::Inbound => {
                    add_rule::<Ipv4Addr>(
                        &mut batch,
                        chain,
                        spec,
                        in_v4.as_set(),
                        libc::NFPROTO_IPV4 as u8,
                    );
                    add_rule::<Ipv6Addr>(
                        &mut batch,
                        chain,
                        spec,
                        in_v6.as_set(),
                        libc::NFPROTO_IPV6 as u8,
                    );
                }
                Direction::Outbound => {
                    add_rule::<Ipv4Addr>(
                        &mut batch,
                        chain,
                        spec,
                        out_v4.as_set(),
                        libc::NFPROTO_IPV4 as u8,
                    );
                    add_rule::<Ipv6Addr>(
                        &mut batch,
                        chain,
                        spec,
                        out_v6.as_set(),
                        libc::NFPROTO_IPV6 as u8,
                    );
                }
            }
        }
        send_and_process(&batch.finalize())
    }

    fn interval_set<'a, T: SetKey>(name: &CStr, id: u32, table: &'a Table) -> IntervalSet<'a, T> {
        IntervalSet::new(name, id, table)
    }

    fn add_v4_intervals(
        set: &mut IntervalSet<'_, Ipv4Addr>,
        nets: &[ipnet::Ipv4Net],
    ) -> io::Result<()> {
        for interval in ipv4_intervals(nets) {
            set.add_range(&interval.first, interval.after_last.as_ref())?;
        }
        Ok(())
    }
    fn add_v6_intervals(
        set: &mut IntervalSet<'_, Ipv6Addr>,
        nets: &[ipnet::Ipv6Net],
    ) -> io::Result<()> {
        for interval in ipv6_intervals(nets) {
            set.add_range(&interval.first, interval.after_last.as_ref())?;
        }
        Ok(())
    }
    fn add_set<T: SetKey>(batch: &mut Batch, set: &IntervalSet<'_, T>) {
        batch.add(set.as_set(), MsgType::Add);
        batch.add_iter(set.as_set().elems_iter(), MsgType::Add);
    }

    fn add_rule<T: SetKey>(
        batch: &mut Batch,
        chain: &Chain<'_>,
        spec: &RenderedRule,
        set: &Set<'_, T>,
        family: u8,
    ) {
        use nftnl::expr::{
            InterfaceName, Ipv4HeaderField, Ipv6HeaderField, NetworkHeaderField, Payload,
        };
        let mut rule = Rule::new(chain);
        if let Some(name) = &spec.ingress {
            rule.add_expr(&nft_expr!(meta iifname));
            rule.add_expr(&nft_expr!(
                cmp == InterfaceName::Exact(
                    CString::new(name.as_str()).expect("validated interface")
                )
            ));
        }
        if let Some(name) = &spec.egress {
            rule.add_expr(&nft_expr!(meta oifname));
            rule.add_expr(&nft_expr!(
                cmp == InterfaceName::Exact(
                    CString::new(name.as_str()).expect("validated interface")
                )
            ));
        }
        rule.add_expr(&nft_expr!(meta nfproto));
        rule.add_expr(&nft_expr!(cmp == family));
        let payload = match (family as i32, spec.address) {
            (libc::NFPROTO_IPV4, AddressField::Source) => {
                Payload::Network(NetworkHeaderField::Ipv4(Ipv4HeaderField::Saddr))
            }
            (libc::NFPROTO_IPV4, AddressField::Destination) => {
                Payload::Network(NetworkHeaderField::Ipv4(Ipv4HeaderField::Daddr))
            }
            (_, AddressField::Source) => {
                Payload::Network(NetworkHeaderField::Ipv6(Ipv6HeaderField::Saddr))
            }
            (_, AddressField::Destination) => {
                Payload::Network(NetworkHeaderField::Ipv6(Ipv6HeaderField::Daddr))
            }
        };
        rule.add_expr(&payload);
        rule.add_expr(&nft_expr!(lookup set));
        rule.add_expr(&nft_expr!(verdict drop));
        batch.add(&rule, MsgType::Add);
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

    // Query all flowtables through NETLINK_NETFILTER and parse their interface device arrays.
    fn flowtable_conflicts(protected: &BTreeSet<String>) -> io::Result<BTreeSet<String>> {
        #[derive(Default)]
        struct DumpState {
            devices: BTreeSet<String>,
            error: Option<io::Error>,
        }

        fn collect(message: &libc::nlmsghdr, state: &mut DumpState) -> libc::c_int {
            let result = Flowtable::parse(message).and_then(|table| table.device_names());
            match result {
                Ok(devices) => {
                    state.devices.extend(devices);
                    mnl::mnl_sys::MNL_CB_OK
                }
                Err(error) => {
                    state.error = Some(error);
                    mnl::mnl_sys::MNL_CB_ERROR
                }
            }
        }

        let seq = 1u32;
        let request = NetlinkRequest::flowtable_dump(seq)?;
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
        let portid = socket.portid();
        socket.send(request.as_bytes())?;
        let mut buffer = AlignedNetlinkBuffer::new(nftnl::nft_nlmsg_maxsize() as usize);
        let mut state = DumpState::default();
        loop {
            let len = socket.recv_raw(buffer.as_bytes_mut())?;
            let response = buffer.prefix(len)?;
            let callback_result = mnl::cb_run2(response, seq, portid, collect, &mut state);
            if let Some(error) = state.error.take() {
                return Err(error);
            }
            if matches!(callback_result?, mnl::CbResult::Stop) {
                break;
            }
        }
        Ok(state.devices.intersection(protected).cloned().collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn large_element_batches_are_split_into_multiple_pages() {
            let table = Table::new(c"page-test", ProtoFamily::Inet);
            let mut set = interval_set::<Ipv4Addr>(c"addresses", 1, &table);
            for value in 0..20_000u32 {
                let address = Ipv4Addr::from(value);
                set.add_range(&address, None).unwrap();
            }
            let mut batch = Batch::with_page_size(65_536);
            batch.add(&table, MsgType::Add);
            add_set(&mut batch, &set);
            assert!(batch.finalize().iter().count() > 1);
        }
    }
}

#[cfg(test)]
pub mod test_backend {
    use super::*;

    #[derive(Default)]
    pub struct MemoryBackend {
        pub active: Option<Snapshot>,
        pub applies: usize,
        pub fail_next: bool,
    }
    impl Backend for MemoryBackend {
        fn apply(
            &mut self,
            _: &Config,
            _: &[RenderedRule],
            snapshot: &Snapshot,
        ) -> Result<(), BackendError> {
            self.applies += 1;
            if std::mem::take(&mut self.fail_next) {
                return Err(std::io::Error::other("injected batch error").into());
            }
            self.active = Some(snapshot.clone());
            Ok(())
        }
        fn flowtable_conflicts(
            &mut self,
            _: &BTreeSet<String>,
        ) -> Result<BTreeSet<String>, BackendError> {
            Ok(BTreeSet::new())
        }
        fn apply_direction(
            &mut self,
            _: &Config,
            _: &[RenderedRule],
            _: crate::config::Direction,
            snapshot: &Snapshot,
        ) -> Result<(), BackendError> {
            self.applies += 1;
            if std::mem::take(&mut self.fail_next) {
                return Err(std::io::Error::other("injected batch error").into());
            }
            self.active = Some(snapshot.clone());
            Ok(())
        }
    }
}
