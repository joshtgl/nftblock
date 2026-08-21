use crate::{
    config::Direction,
    zones::{Chain, ResolvedRule},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressField {
    Source,
    Destination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedRule {
    pub chain: Chain,
    pub direction: Direction,
    pub ingress: Option<String>,
    pub egress: Option<String>,
    pub address: AddressField,
}

/// Expand zone alternatives to concrete rules. nftables expressions inside one rule are ANDed,
/// while separate rules provide the intended OR semantics for interfaces in a zone.
pub fn render(rules: &[ResolvedRule]) -> Vec<RenderedRule> {
    let mut out = Vec::new();
    for rule in rules {
        let ingress: Vec<Option<&String>> = if rule.ingress.is_empty() {
            vec![None]
        } else {
            rule.ingress.iter().map(Some).collect()
        };
        let egress: Vec<Option<&String>> = if rule.egress.is_empty() {
            vec![None]
        } else {
            rule.egress.iter().map(Some).collect()
        };
        for iif in &ingress {
            for oif in &egress {
                out.push(RenderedRule {
                    chain: rule.chain,
                    direction: rule.blocklist,
                    ingress: iif.map(|v| (*v).clone()),
                    egress: oif.map(|v| (*v).clone()),
                    address: match rule.blocklist {
                        Direction::Inbound => AddressField::Source,
                        Direction::Outbound => AddressField::Destination,
                    },
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_mapping_is_a_cross_product() {
        let mappings = vec![ResolvedRule {
            chain: Chain::Forward,
            blocklist: Direction::Inbound,
            ingress: vec!["wan0".into(), "wan1".into()],
            egress: vec!["lan0".into(), "lan1".into()],
        }];
        let rendered = render(&mappings);
        assert_eq!(rendered.len(), 4);
        assert!(rendered.iter().all(|r| r.address == AddressField::Source));
    }
}
