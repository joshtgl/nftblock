use crate::config::{Direction, RuleMapping, Rules};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, de};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ZonesDocument {
    List { zones: Vec<ZoneEntry> },
    Map(BTreeMap<String, ZoneValue>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ZoneValue {
    Interfaces(Vec<String>),
    Detail {
        #[serde(default)]
        interfaces: Vec<String>,
        #[serde(default)]
        local: bool,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct ZoneEntry {
    name: String,
    #[serde(default)]
    interfaces: Vec<String>,
    #[serde(default)]
    local: bool,
}

#[derive(Debug, Clone)]
struct Zone {
    interfaces: Vec<String>,
    local: bool,
}

#[derive(Debug, Clone)]
pub struct Zones(BTreeMap<String, Zone>);

impl<'de> Deserialize<'de> for Zones {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = BTreeMap::<String, ZoneValue>::deserialize(deserializer)?;
        Self::from_map(map).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Input,
    Forward,
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRule {
    pub chain: Chain,
    pub blocklist: Direction,
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
}

impl Zones {
    pub fn interfaces(&self, names: &[String]) -> Result<Vec<String>> {
        self.expand(names, false)
    }
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let doc: ZonesDocument =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        let entries = match doc {
            ZonesDocument::List { zones } => zones,
            ZonesDocument::Map(map) => return Self::from_map(map),
        };
        Self::from_entries(entries)
    }

    fn from_map(map: BTreeMap<String, ZoneValue>) -> Result<Self> {
        Self::from_entries(map.into_iter().map(|(name, value)| match value {
            ZoneValue::Interfaces(interfaces) => ZoneEntry {
                local: name.eq_ignore_ascii_case("LOCAL"),
                name,
                interfaces,
            },
            ZoneValue::Detail { interfaces, local } => ZoneEntry {
                name,
                interfaces,
                local,
            },
        }))
    }

    fn from_entries(entries: impl IntoIterator<Item = ZoneEntry>) -> Result<Self> {
        let mut zones = BTreeMap::new();
        for entry in entries {
            if entry.name.trim().is_empty() {
                bail!("zone has an empty name")
            }
            let local = entry.local || entry.name.eq_ignore_ascii_case("LOCAL");
            if !local && entry.interfaces.is_empty() {
                bail!("non-local zone {:?} has no interfaces", entry.name)
            }
            if entry
                .interfaces
                .iter()
                .any(|i| i.is_empty() || i.as_bytes().contains(&0))
            {
                bail!("zone {:?} has an invalid interface", entry.name)
            }
            if zones
                .insert(
                    entry.name.clone(),
                    Zone {
                        interfaces: entry.interfaces,
                        local,
                    },
                )
                .is_some()
            {
                bail!("duplicate zone {:?}", entry.name)
            }
        }
        Ok(Self(zones))
    }

    pub fn resolve(&self, rules: &Rules) -> Result<Vec<ResolvedRule>> {
        let mut result = Vec::new();
        for rule in &rules.input {
            result.push(self.resolve_one(Chain::Input, rule)?);
        }
        for rule in &rules.forward {
            result.push(self.resolve_one(Chain::Forward, rule)?);
        }
        for rule in &rules.output {
            result.push(self.resolve_one(Chain::Output, rule)?);
        }
        Ok(result)
    }

    fn resolve_one(&self, chain: Chain, rule: &RuleMapping) -> Result<ResolvedRule> {
        match chain {
            Chain::Input if !rule.egress_zones.is_empty() => {
                bail!("input rule cannot have egress_zones")
            }
            Chain::Output if !rule.ingress_zones.is_empty() => {
                bail!("output rule cannot have ingress_zones")
            }
            Chain::Forward if rule.ingress_zones.is_empty() || rule.egress_zones.is_empty() => {
                bail!("forward rule requires ingress_zones and egress_zones")
            }
            _ => {}
        }
        let ingress = self.expand(&rule.ingress_zones, chain == Chain::Forward)?;
        let egress = self.expand(&rule.egress_zones, chain == Chain::Forward)?;
        Ok(ResolvedRule {
            chain,
            blocklist: rule.blocklist,
            ingress,
            egress,
        })
    }

    fn expand(&self, names: &[String], forward: bool) -> Result<Vec<String>> {
        let mut interfaces = BTreeSet::new();
        for name in names {
            let zone = self
                .0
                .get(name)
                .with_context(|| format!("unknown zone {name:?}"))?;
            if forward && zone.local {
                bail!("local zone {name:?} cannot be used as a forward interface")
            }
            interfaces.extend(zone.interfaces.iter().cloned());
        }
        Ok(interfaces.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Direction, RuleMapping};
    use std::io::Write;

    fn zones() -> Zones {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, r#"{{"WAN":["eth0"],"LAN":{{"interfaces":["eth1"],"local":false}},"LOCAL":{{"interfaces":[],"local":true}}}}"#).unwrap();
        Zones::load(file.path()).unwrap()
    }

    #[test]
    fn resolves_multiple_mappings_and_interfaces() {
        let rules = Rules {
            input: vec![RuleMapping {
                blocklist: Direction::Inbound,
                ingress_zones: vec!["WAN".into()],
                egress_zones: vec![],
            }],
            forward: vec![],
            output: vec![],
        };
        assert_eq!(zones().resolve(&rules).unwrap()[0].ingress, vec!["eth0"]);
    }

    #[test]
    fn rejects_local_forward_zone() {
        let rules = Rules {
            input: vec![],
            forward: vec![RuleMapping {
                blocklist: Direction::Inbound,
                ingress_zones: vec!["LOCAL".into()],
                egress_zones: vec!["WAN".into()],
            }],
            output: vec![],
        };
        assert!(
            zones()
                .resolve(&rules)
                .unwrap_err()
                .to_string()
                .contains("local zone")
        );
    }
}
