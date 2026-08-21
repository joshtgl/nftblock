use crate::{
    blocklist,
    config::{Config, Direction, open_blocklist},
    netlink::{Backend, BackendError, Snapshot},
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
    known: BTreeSet<Direction>,
    snapshot: Snapshot,
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
            known: BTreeSet::new(),
            snapshot: Snapshot::default(),
            backend,
        })
    }

    pub fn start(mut self) -> Result<()> {
        self.initial_load()?;
        self.watch()
    }

    fn initial_load(&mut self) -> Result<()> {
        let inbound = self.read(Direction::Inbound);
        let outbound = self.read(Direction::Outbound);
        match (inbound, outbound) {
            (Ok(inbound), Ok(outbound)) => {
                let snapshot = Snapshot { inbound, outbound };
                self.backend.apply(&self.config, &self.rules, &snapshot)?;
                self.snapshot = snapshot;
                self.known.extend([Direction::Inbound, Direction::Outbound]);
                log::info!("installed initial inbound and outbound blocklists");
            }
            (inbound, outbound) => {
                match inbound {
                    Ok(parsed) => self.install_initial_direction(Direction::Inbound, parsed)?,
                    Err(error) => log::error!(
                        "inbound startup list rejected; preserving its existing kernel sets: {error:#}"
                    ),
                }
                match outbound {
                    Ok(parsed) => self.install_initial_direction(Direction::Outbound, parsed)?,
                    Err(error) => log::error!(
                        "outbound startup list rejected; preserving its existing kernel sets: {error:#}"
                    ),
                }
            }
        }
        Ok(())
    }

    fn install_initial_direction(
        &mut self,
        direction: Direction,
        parsed: blocklist::ParsedBlocklist,
    ) -> Result<()> {
        match direction {
            Direction::Inbound => self.snapshot.inbound = parsed,
            Direction::Outbound => self.snapshot.outbound = parsed,
        }
        self.backend
            .apply_direction(&self.config, &self.rules, direction, &self.snapshot)?;
        self.known.insert(direction);
        Ok(())
    }

    fn read(&self, direction: Direction) -> Result<blocklist::ParsedBlocklist> {
        let path = self.path(direction);
        blocklist::parse(open_blocklist(path)?).with_context(|| format!("parse {}", path.display()))
    }

    pub fn reload(&mut self, direction: Direction) -> Result<()> {
        let parsed = self.read(direction)?;
        let mut candidate = self.snapshot.clone();
        match direction {
            Direction::Inbound => candidate.inbound = parsed,
            Direction::Outbound => candidate.outbound = parsed,
        }
        self.backend
            .apply_direction(&self.config, &self.rules, direction, &candidate)?;
        self.snapshot = candidate;
        self.known.insert(direction);
        log::info!("reloaded {:?} blocklist", direction);
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
                if let Err(error) = self.reload(direction) {
                    log::error!(
                        "{:?} replacement rejected; active sets retained: {error:#}",
                        direction
                    );
                }
            }
            if now >= next_reconcile {
                check_flowtables(&self.config, &mut self.backend, &self.protected)?;
                if self.known.len() == 2 {
                    if let Err(error) =
                        self.backend
                            .apply(&self.config, &self.rules, &self.snapshot)
                    {
                        log::error!("table reconciliation failed; current table retained: {error}");
                    }
                } else {
                    log::warn!(
                        "full table reconciliation deferred until both directional files have been loaded successfully"
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
    fn failed_batch_does_not_advance_active_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path());
        fs::write(&cfg.files.inbound, "10.0.0.0/8\n").unwrap();
        fs::write(&cfg.files.outbound, "2001:db8::/32\n").unwrap();
        let mut daemon = Daemon::new(cfg, MemoryBackend::default()).unwrap();
        daemon.initial_load().unwrap();
        let old = daemon.snapshot.clone();
        fs::write(&daemon.config.files.inbound, "192.0.2.0/24\n").unwrap();
        daemon.backend.fail_next = true;
        assert!(daemon.reload(Direction::Inbound).is_err());
        assert_eq!(daemon.snapshot, old);
    }
}
