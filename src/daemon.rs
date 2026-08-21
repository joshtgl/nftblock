use crate::{
    blocklist,
    config::{Config, Direction, open_blocklist},
    netlink::{
        ActiveGenerations, Backend, BackendError, DirectionGeneration, Health, LayoutStatus,
        apply_stats,
    },
    rules::{RenderedRule, render},
};
use anyhow::{Context, Result, bail};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

pub struct Daemon<B> {
    config: Config,
    rules: Vec<RenderedRule>,
    protected: BTreeSet<String>,
    active: Option<ActiveGenerations>,
    backend: B,
}

impl<B: Backend> Daemon<B> {
    pub fn new(config: Config, mut backend: B) -> Result<Self> {
        let zones = config.load_zones()?;
        let rules = render(&config.resolve_rules(&zones)?);
        let protected = rules
            .iter()
            .flat_map(|rule| rule.ingress.iter().chain(rule.egress.iter()))
            .cloned()
            .collect();
        check_flowtables(&config, &mut backend, &protected)?;
        Ok(Self {
            config,
            rules,
            protected,
            active: None,
            backend,
        })
    }

    pub fn start(mut self) -> Result<()> {
        self.initial_load()?;
        self.watch()
    }

    fn initial_load(&mut self) -> Result<()> {
        log::info!(
            "blocklist load triggered: reason=startup table=inet {}",
            self.config.nftables.table
        );
        match self.backend.layout_status(&self.config)? {
            LayoutStatus::Absent => self.backend.bootstrap(&self.config, &self.rules)?,
            LayoutStatus::Current => {}
            LayoutStatus::Incompatible => bail!(
                "table inet {} uses an unsupported pre-generation layout; remove it before starting nftblock",
                self.config.nftables.table
            ),
        }
        if let Err(error) = self.load_both("startup") {
            log::error!(
                "startup blocklists rejected; preserving the existing generation: {error:#}"
            );
        }
        Ok(())
    }

    fn stage(&mut self, direction: Direction, reason: &str) -> Result<DirectionGeneration> {
        let path = self.path(direction).to_path_buf();
        let reader = open_blocklist(&path)?;
        let mut stage = self.backend.begin_stage(&self.config, direction)?;
        log::info!(
            "staging blocklist: reason={reason} direction={} path={} ipv4_set={} ipv6_set={}",
            direction_name(direction),
            path.display(),
            stage.ipv4_set,
            stage.ipv6_set
        );
        let result = blocklist::stream_chunks(
            reader,
            self.config.nftables.populate_batch_elements as usize,
            |chunk| {
                self.backend
                    .populate(&self.config, &stage, chunk)
                    .map_err(Into::into)
            },
        )
        .with_context(|| format!("stage {}", path.display()));
        match result {
            Ok(stats) => {
                log::info!(
                    "staged blocklist: reason={reason} direction={} path={} source_cidrs={} boundary_elements={} ipv4_boundary_elements={} ipv6_boundary_elements={} ipv4_set={} ipv6_set={}",
                    direction_name(direction),
                    path.display(),
                    stats.cidrs,
                    stats.ipv4_boundaries + stats.ipv6_boundaries,
                    stats.ipv4_boundaries,
                    stats.ipv6_boundaries,
                    stage.ipv4_set,
                    stage.ipv6_set
                );
                apply_stats(&mut stage, stats);
                Ok(stage)
            }
            Err(error) => {
                if let Err(cleanup) = self.backend.discard(&self.config, &stage) {
                    log::error!("failed to discard rejected staging sets: {cleanup}");
                }
                Err(error)
            }
        }
    }

    fn load_both(&mut self, reason: &str) -> Result<()> {
        let inbound = self.stage(Direction::Inbound, reason)?;
        let outbound = match self.stage(Direction::Outbound, reason) {
            Ok(value) => value,
            Err(error) => {
                if let Err(cleanup) = self.backend.discard(&self.config, &inbound) {
                    log::error!("failed to discard inbound staging sets: {cleanup}");
                }
                return Err(error);
            }
        };
        let candidate = ActiveGenerations { inbound, outbound };
        if let Err(error) = self
            .backend
            .activate_initial(&self.config, &self.rules, &candidate)
        {
            for stage in [&candidate.inbound, &candidate.outbound] {
                if let Err(cleanup) = self.backend.discard(&self.config, stage) {
                    log::error!("failed to discard unactivated staging sets: {cleanup}");
                }
            }
            return Err(error.into());
        }
        self.active = Some(candidate.clone());
        if let Err(error) = self.backend.cleanup_obsolete(&self.config, &candidate) {
            log::error!("obsolete generation cleanup deferred: {error}");
        }
        log::info!(
            "activated blocklist generations: reason={reason} inbound_ipv4_set={} inbound_ipv4_boundary_elements={} inbound_ipv6_set={} inbound_ipv6_boundary_elements={} outbound_ipv4_set={} outbound_ipv4_boundary_elements={} outbound_ipv6_set={} outbound_ipv6_boundary_elements={}",
            candidate.inbound.ipv4_set,
            candidate.inbound.ipv4_boundaries,
            candidate.inbound.ipv6_set,
            candidate.inbound.ipv6_boundaries,
            candidate.outbound.ipv4_set,
            candidate.outbound.ipv4_boundaries,
            candidate.outbound.ipv6_set,
            candidate.outbound.ipv6_boundaries
        );
        Ok(())
    }

    pub fn reload(&mut self, direction: Direction) -> Result<()> {
        self.reload_for(direction, "requested reload")
    }

    fn reload_for(&mut self, direction: Direction, reason: &str) -> Result<()> {
        if self.active.is_none() {
            return self.load_both(reason);
        }
        log::info!(
            "blocklist reload triggered: reason={reason} direction={}",
            direction_name(direction)
        );
        let stage = self.stage(direction, reason)?;
        if let Err(error) = self
            .backend
            .activate_direction(&self.config, direction, &stage)
        {
            if let Err(cleanup) = self.backend.discard(&self.config, &stage) {
                log::error!("failed to discard unactivated staging sets: {cleanup}");
            }
            return Err(error.into());
        }
        let active = self.active.as_mut().expect("checked active state");
        match direction {
            Direction::Inbound => active.inbound = stage,
            Direction::Outbound => active.outbound = stage,
        }
        let active = active.clone();
        if let Err(error) = self.backend.cleanup_obsolete(&self.config, &active) {
            log::error!("obsolete generation cleanup deferred: {error}");
        }
        let generation = match direction {
            Direction::Inbound => &active.inbound,
            Direction::Outbound => &active.outbound,
        };
        log::info!(
            "activated blocklist generation: reason={reason} direction={} ipv4_set={} ipv4_boundary_elements={} ipv6_set={} ipv6_boundary_elements={}",
            direction_name(direction),
            generation.ipv4_set,
            generation.ipv4_boundaries,
            generation.ipv6_set,
            generation.ipv6_boundaries
        );
        Ok(())
    }

    fn path(&self, direction: Direction) -> &Path {
        match direction {
            Direction::Inbound => &self.config.files.inbound,
            Direction::Outbound => &self.config.files.outbound,
        }
    }

    fn watch(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel();
        let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |event| {
            let _ = tx.send(event);
        })?;
        let parents = [
            self.config.files.inbound.parent(),
            self.config.files.outbound.parent(),
        ];
        let mut watched = BTreeSet::new();
        for parent in parents.into_iter().flatten() {
            if watched.insert(parent.to_path_buf()) {
                watcher.watch(parent, RecursiveMode::NonRecursive)?;
            }
        }
        if watched.is_empty() {
            bail!("blocklist files must have parent directories")
        }

        let stopping = Arc::new(AtomicBool::new(false));
        for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            signal_hook::flag::register(signal, Arc::clone(&stopping))?;
        }
        let mut pending: HashMap<Direction, Instant> = HashMap::new();
        let mut next_reconcile = Instant::now() + self.config.reconcile();
        while !stopping.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(event)) => {
                    for direction in classify_event(
                        &event,
                        &self.config.files.inbound,
                        &self.config.files.outbound,
                    ) {
                        pending.insert(direction, Instant::now() + self.config.debounce());
                    }
                }
                Ok(Err(error)) => log::error!("filesystem watcher error: {error}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => bail!("filesystem watcher stopped"),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = Instant::now();
            let due: Vec<_> = pending
                .iter()
                .filter_map(|(direction, deadline)| (*deadline <= now).then_some(*direction))
                .collect();
            for direction in due {
                pending.remove(&direction);
                if let Err(error) = self.reload_for(direction, "filesystem change") {
                    log::error!(
                        "{:?} replacement rejected; active sets retained: {error:#}",
                        direction
                    );
                }
            }
            if now >= next_reconcile {
                log::info!(
                    "reconciliation triggered: reason=periodic interval_secs={}",
                    self.config.runtime.reconcile_secs
                );
                check_flowtables(&self.config, &mut self.backend, &self.protected)?;
                if let Err(error) = self.reconcile() {
                    log::error!(
                        "table reconciliation failed; current generation retained: {error:#}"
                    );
                }
                next_reconcile = now + self.config.reconcile();
            }
        }
        log::info!(
            "shutdown requested; preserving table inet {}",
            self.config.nftables.table
        );
        Ok(())
    }

    fn reconcile(&mut self) -> Result<()> {
        let Some(active) = self.active.clone() else {
            log::warn!("reconciliation found no active generation; repopulating both blocklists");
            return self.load_both("periodic reconciliation found no active generation");
        };
        match self.backend.layout_status(&self.config)? {
            LayoutStatus::Absent => {
                log::warn!(
                    "reconciliation found table inet {} absent; repopulating both blocklists",
                    self.config.nftables.table
                );
                self.backend.bootstrap(&self.config, &self.rules)?;
                return self.load_both("periodic reconciliation found table absent");
            }
            LayoutStatus::Incompatible => bail!(
                "table inet {} lost its generation-layout marker; refusing to modify an unversioned table",
                self.config.nftables.table
            ),
            LayoutStatus::Current => {}
        }
        match self.backend.health(&self.config, &active)? {
            Health::Healthy => {
                self.backend
                    .repair_rules(&self.config, &self.rules, &active)?;
                log::info!(
                    "reconciliation complete: generation element counts healthy; rules_repaired=true sets_repopulated=false inbound_ipv4_set={} inbound_ipv6_set={} outbound_ipv4_set={} outbound_ipv6_set={}",
                    active.inbound.ipv4_set,
                    active.inbound.ipv6_set,
                    active.outbound.ipv4_set,
                    active.outbound.ipv6_set
                );
            }
            Health::InboundDamaged => self.reload_for(
                Direction::Inbound,
                "periodic reconciliation found inbound set damage",
            )?,
            Health::OutboundDamaged => self.reload_for(
                Direction::Outbound,
                "periodic reconciliation found outbound set damage",
            )?,
            Health::LayoutDamaged => {
                log::warn!(
                    "reconciliation found multiple missing or mismatched sets; repopulating both blocklists"
                );
                self.load_both("periodic reconciliation found layout damage")?;
            }
        }
        Ok(())
    }
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
    }
}

fn check_flowtables<B: Backend>(
    config: &Config,
    backend: &mut B,
    protected: &BTreeSet<String>,
) -> Result<()> {
    if config.nftables.allow_flowtable_bypass {
        return Ok(());
    }
    let conflicts = backend.flowtable_conflicts(protected)?;
    if !conflicts.is_empty() {
        return Err(BackendError::FlowtableBypass(conflicts).into());
    }
    Ok(())
}

pub fn classify_event(event: &Event, inbound: &Path, outbound: &Path) -> BTreeSet<Direction> {
    let mut found = BTreeSet::new();
    for path in &event.paths {
        if same_target(path, inbound) {
            found.insert(Direction::Inbound);
        }
        if same_target(path, outbound) {
            found.insert(Direction::Outbound);
        }
    }
    found
}

fn same_target(event_path: &Path, target: &Path) -> bool {
    event_path == target
        || (event_path.parent() == target.parent() && event_path.file_name() == target.file_name())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Files, Nftables, RuleMapping, Rules, Runtime},
        netlink::test_backend::MemoryBackend,
    };
    use notify::{
        EventKind,
        event::{ModifyKind, RenameMode},
    };
    use std::{fs, path::PathBuf};

    fn config(root: &Path) -> Config {
        fs::write(root.join("zones.json"), r#"{"WAN":["eth0"]}"#).unwrap();
        Config {
            files: Files {
                zones: Some(root.join("zones.json")),
                inbound: root.join("inbound.txt"),
                outbound: root.join("outbound.txt"),
            },
            zones: None,
            nftables: Nftables::default(),
            runtime: Runtime::default(),
            rules: Rules {
                input: vec![RuleMapping {
                    blocklist: Direction::Inbound,
                    ingress_zones: vec!["WAN".into()],
                    egress_zones: vec![],
                }],
                forward: vec![],
                output: vec![],
            },
        }
    }

    #[test]
    fn recognizes_atomic_rename_destination() {
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            paths: vec![
                PathBuf::from("/lists/.inbound.tmp"),
                PathBuf::from("/lists/inbound.txt"),
            ],
            attrs: Default::default(),
        };
        assert!(
            classify_event(
                &event,
                Path::new("/lists/inbound.txt"),
                Path::new("/lists/outbound.txt")
            )
            .contains(&Direction::Inbound)
        );
    }

    #[test]
    fn failed_activation_does_not_advance_active_generation() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        fs::write(&cfg.files.inbound, "10.0.0.0/8\n").unwrap();
        fs::write(&cfg.files.outbound, "2001:db8::/32\n").unwrap();
        let mut daemon = Daemon::new(cfg, MemoryBackend::default()).unwrap();
        daemon.initial_load().unwrap();
        let old = daemon.active.clone();
        fs::write(&daemon.config.files.inbound, "192.0.2.0/24\n").unwrap();
        daemon.backend.fail_next = true;
        assert!(daemon.reload(Direction::Inbound).is_err());
        assert_eq!(daemon.active, old);
    }

    #[test]
    fn late_parse_failure_after_a_chunk_preserves_active_generation() {
        let root = tempfile::tempdir().unwrap();
        let mut cfg = config(root.path());
        cfg.nftables.populate_batch_elements = 2;
        fs::write(&cfg.files.inbound, "10.0.0.0/32\n").unwrap();
        fs::write(&cfg.files.outbound, "2001:db8::/128\n").unwrap();
        let mut daemon = Daemon::new(cfg, MemoryBackend::default()).unwrap();
        daemon.initial_load().unwrap();
        let old = daemon.active.clone();
        let chunks_before = daemon.backend.chunks.len();
        fs::write(
            &daemon.config.files.inbound,
            "10.0.0.2/32\n10.0.0.4/32\nnot-a-cidr\n",
        )
        .unwrap();
        assert!(daemon.reload(Direction::Inbound).is_err());
        assert_eq!(daemon.active, old);
        assert!(daemon.backend.chunks.len() > chunks_before);
        assert!(daemon.backend.chunks.iter().all(|count| *count <= 2));
    }

    #[test]
    fn incompatible_layout_fails_without_bootstrapping() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        fs::write(&cfg.files.inbound, "10.0.0.0/8\n").unwrap();
        fs::write(&cfg.files.outbound, "2001:db8::/32\n").unwrap();
        let backend = MemoryBackend {
            layout: Some(LayoutStatus::Incompatible),
            ..Default::default()
        };
        let mut daemon = Daemon::new(cfg, backend).unwrap();
        let error = daemon.initial_load().unwrap_err().to_string();
        assert!(error.contains("unsupported pre-generation layout"));
        assert_eq!(daemon.backend.layout, Some(LayoutStatus::Incompatible));
        assert!(daemon.backend.chunks.is_empty());
    }

    #[test]
    fn healthy_reconciliation_refreshes_rules_without_repopulating_sets() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        fs::write(&cfg.files.inbound, "10.0.0.0/8\n").unwrap();
        fs::write(&cfg.files.outbound, "2001:db8::/32\n").unwrap();
        let mut daemon = Daemon::new(cfg, MemoryBackend::default()).unwrap();
        daemon.initial_load().unwrap();
        let active = daemon.active.clone();
        let chunks = daemon.backend.chunks.clone();
        let generation = daemon.backend.generation;

        daemon.reconcile().unwrap();

        assert_eq!(daemon.active, active);
        assert_eq!(daemon.backend.chunks, chunks);
        assert_eq!(daemon.backend.generation, generation);
        assert_eq!(daemon.backend.repairs, 1);
    }

    #[test]
    fn damaged_inbound_reconciliation_repopulates_only_inbound_sets() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        fs::write(&cfg.files.inbound, "10.0.0.0/8\n").unwrap();
        fs::write(&cfg.files.outbound, "2001:db8::/32\n").unwrap();
        let mut daemon = Daemon::new(cfg, MemoryBackend::default()).unwrap();
        daemon.initial_load().unwrap();
        let old = daemon.active.clone().unwrap();
        let generation = daemon.backend.generation;
        daemon.backend.health = Some(Health::InboundDamaged);

        daemon.reconcile().unwrap();

        let active = daemon.active.as_ref().unwrap();
        assert_ne!(active.inbound, old.inbound);
        assert_eq!(active.outbound, old.outbound);
        assert_eq!(daemon.backend.generation, generation + 1);
        assert_eq!(daemon.backend.repairs, 0);
    }
}
