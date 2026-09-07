use crate::zones::{ResolvedRule, Zones};
use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[arg(
        long,
        env = "NFTBLOCK_CONFIG",
        default_value = "/etc/nftblock/nftblock.toml"
    )]
    pub config: PathBuf,
    #[arg(long, env = "NFTBLOCK_ZONES")]
    pub zones: Option<PathBuf>,
    #[arg(long, env = "NFTBLOCK_INBOUND")]
    pub inbound: Option<PathBuf>,
    #[arg(long, env = "NFTBLOCK_OUTBOUND")]
    pub outbound: Option<PathBuf>,
    #[arg(long, env = "NFTBLOCK_TABLE")]
    pub table: Option<String>,
    #[arg(long, env = "NFTBLOCK_PRIORITY")]
    pub priority: Option<i32>,
    #[arg(long, env = "NFTBLOCK_DEBOUNCE_MS")]
    pub debounce_ms: Option<u64>,
    #[arg(long, env = "NFTBLOCK_RECONCILE_SECS")]
    pub reconcile_secs: Option<u64>,
    #[arg(long, env = "NFTBLOCK_ALLOW_FLOWTABLE_BYPASS")]
    pub allow_flowtable_bypass: Option<bool>,
    #[arg(long, env = "NFTBLOCK_POPULATE_BATCH_ELEMENTS")]
    pub populate_batch_elements: Option<u32>,
    #[arg(long, help = "Validate configuration and print the resolved rules")]
    pub check: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub files: Files,
    #[serde(default)]
    pub zones: Option<Zones>,
    #[serde(default)]
    pub nftables: Nftables,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub rules: Rules,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    #[serde(default)]
    pub zones: Option<PathBuf>,
    #[serde(default)]
    pub inbound: Option<PathBuf>,
    #[serde(default)]
    pub outbound: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Nftables {
    pub table: String,
    pub priority: i32,
    pub allow_flowtable_bypass: bool,
    pub batch_page_bytes: u32,
    pub populate_batch_elements: u32,
}
impl Default for Nftables {
    fn default() -> Self {
        Self {
            table: "nftblock".into(),
            priority: -5,
            allow_flowtable_bypass: false,
            batch_page_bytes: 128 * 1024,
            populate_batch_elements: 2_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Runtime {
    pub debounce_ms: u64,
    pub reconcile_secs: u64,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            debounce_ms: 500,
            reconcile_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub input: Vec<RuleMapping>,
    pub forward: Vec<RuleMapping>,
    pub output: Vec<RuleMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMapping {
    pub blocklist: Direction,
    #[serde(default)]
    pub ingress_zones: Vec<String>,
    #[serde(default)]
    pub egress_zones: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Config {
    pub fn load(cli: &Cli) -> Result<Self> {
        let text = std::fs::read_to_string(&cli.config)
            .with_context(|| format!("read {}", cli.config.display()))?;
        let mut value: Self =
            toml::from_str(&text).with_context(|| format!("parse {}", cli.config.display()))?;
        if let Some(v) = &cli.zones {
            value.files.zones = Some(v.clone());
            value.zones = None;
        }
        if let Some(v) = &cli.inbound {
            value.files.inbound = Some(v.clone());
        }
        if let Some(v) = &cli.outbound {
            value.files.outbound = Some(v.clone());
        }
        if let Some(v) = &cli.table {
            value.nftables.table = v.clone();
        }
        if let Some(v) = cli.priority {
            value.nftables.priority = v;
        }
        if let Some(v) = cli.debounce_ms {
            value.runtime.debounce_ms = v;
        }
        if let Some(v) = cli.reconcile_secs {
            value.runtime.reconcile_secs = v;
        }
        if let Some(v) = cli.allow_flowtable_bypass {
            value.nftables.allow_flowtable_bypass = v;
        }
        if let Some(v) = cli.populate_batch_elements {
            value.nftables.populate_batch_elements = v;
        }
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.nftables.table.is_empty()
            || self
                .nftables
                .table
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        {
            bail!("invalid nftables table name")
        }
        if self.runtime.debounce_ms == 0 || self.runtime.reconcile_secs == 0 {
            bail!("debounce and reconciliation intervals must be non-zero")
        }
        if self.nftables.batch_page_bytes < 64 * 1024 {
            bail!("batch_page_bytes must be at least 65536")
        }
        if self.nftables.populate_batch_elements == 0 {
            bail!("populate_batch_elements must be non-zero")
        }
        if self.rules.input.is_empty()
            && self.rules.forward.is_empty()
            && self.rules.output.is_empty()
        {
            bail!("at least one rule mapping is required")
        }
        for direction in [Direction::Inbound, Direction::Outbound] {
            if self.uses(direction) && self.blocklist_path(direction).is_none() {
                bail!(
                    "[files].{} is required because a rule references the {} blocklist",
                    direction.name(),
                    direction.name()
                )
            }
        }
        match (&self.files.zones, &self.zones) {
            (None, None) => bail!("zones must be defined in [zones] or [files].zones"),
            (Some(_), Some(_)) => {
                bail!("zones must be defined in only one of [zones] or [files].zones")
            }
            _ => {}
        }
        Ok(())
    }

    pub fn debounce(&self) -> Duration {
        Duration::from_millis(self.runtime.debounce_ms)
    }

    pub fn blocklist_path(&self, direction: Direction) -> Option<&Path> {
        match direction {
            Direction::Inbound => self.files.inbound.as_deref(),
            Direction::Outbound => self.files.outbound.as_deref(),
        }
    }

    pub fn uses(&self, direction: Direction) -> bool {
        self.rules
            .input
            .iter()
            .chain(&self.rules.forward)
            .chain(&self.rules.output)
            .any(|rule| rule.blocklist == direction)
    }
    pub fn reconcile(&self) -> Duration {
        Duration::from_secs(self.runtime.reconcile_secs)
    }

    pub fn resolve_rules(&self, zones: &Zones) -> Result<Vec<ResolvedRule>> {
        zones.resolve(&self.rules)
    }

    pub fn load_zones(&self) -> Result<Zones> {
        match (&self.files.zones, &self.zones) {
            (Some(path), None) => Zones::load(path),
            (None, Some(zones)) => Ok(zones.clone()),
            (None, None) => bail!("zones must be defined in [zones] or [files].zones"),
            (Some(_), Some(_)) => {
                bail!("zones must be defined in only one of [zones] or [files].zones")
            }
        }
    }
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

pub fn open_blocklist(path: &Path) -> Result<std::io::BufReader<std::fs::File>> {
    Ok(std::io::BufReader::new(
        std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE_CONFIG: &str = r#"
[files]
inbound = "/data/inbound.txt"
outbound = "/data/outbound.txt"

[zones]
WAN = ["eth0"]
LOCAL = { interfaces = [], local = true }

[[rules.input]]
blocklist = "inbound"
ingress_zones = ["WAN"]
"#;

    #[test]
    fn accepts_inline_zones_without_a_zones_file() {
        let config: Config = toml::from_str(INLINE_CONFIG).unwrap();
        config.validate().unwrap();

        let rules = config.resolve_rules(&config.load_zones().unwrap()).unwrap();
        assert_eq!(rules[0].ingress, ["eth0"]);
    }

    #[test]
    fn accepts_an_omitted_unused_blocklist() {
        let text = INLINE_CONFIG.replace("outbound = \"/data/outbound.txt\"\n", "");
        let config: Config = toml::from_str(&text).unwrap();

        config.validate().unwrap();
        assert!(config.blocklist_path(Direction::Inbound).is_some());
        assert!(config.blocklist_path(Direction::Outbound).is_none());
    }

    #[test]
    fn rejects_an_omitted_referenced_blocklist() {
        let text = INLINE_CONFIG.replace("inbound = \"/data/inbound.txt\"\n", "");
        let config: Config = toml::from_str(&text).unwrap();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("[files].inbound is required"));
    }

    #[test]
    fn rejects_inline_and_file_zones_together() {
        let text = INLINE_CONFIG.replacen("[files]", "[files]\nzones = \"/data/zones.json\"", 1);
        let config: Config = toml::from_str(&text).unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("only one")
        );
    }

    #[test]
    fn explicit_zones_path_overrides_inline_zones() {
        let root = tempfile::tempdir().unwrap();
        let config_path = root.path().join("nftblock.toml");
        let zones_path = root.path().join("zones.json");
        std::fs::write(&config_path, INLINE_CONFIG).unwrap();
        std::fs::write(&zones_path, r#"{"WAN":["wan0"]}"#).unwrap();
        let cli = Cli {
            config: config_path,
            zones: Some(zones_path),
            inbound: None,
            outbound: None,
            table: None,
            priority: None,
            debounce_ms: None,
            reconcile_secs: None,
            allow_flowtable_bypass: None,
            populate_batch_elements: None,
            check: false,
        };

        let config = Config::load(&cli).unwrap();
        let rules = config.resolve_rules(&config.load_zones().unwrap()).unwrap();
        assert_eq!(rules[0].ingress, ["wan0"]);
    }
}
