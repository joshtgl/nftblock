use ipnet::IpNet;
use std::{
    collections::BTreeSet,
    io::BufRead,
    net::{Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedBlocklist {
    pub ipv4: Vec<ipnet::Ipv4Net>,
    pub ipv6: Vec<ipnet::Ipv6Net>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("I/O while reading blocklist at line {line}: {source}")]
    Io { line: usize, source: std::io::Error },
    #[error("invalid CIDR at line {line}: {text:?}: {source}")]
    Invalid {
        line: usize,
        text: String,
        source: ipnet::AddrParseError,
    },
}

pub fn parse(reader: impl BufRead) -> Result<ParsedBlocklist, ParseError> {
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for (index, line) in reader.lines().enumerate() {
        let number = index + 1;
        let line = line.map_err(|source| ParseError::Io {
            line: number,
            source,
        })?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        match value
            .parse::<IpNet>()
            .map_err(|source| ParseError::Invalid {
                line: number,
                text: value.to_owned(),
                source,
            })? {
            IpNet::V4(net) => {
                v4.insert(net.trunc());
            }
            IpNet::V6(net) => {
                v6.insert(net.trunc());
            }
        }
    }
    Ok(ParsedBlocklist {
        ipv4: v4.into_iter().collect(),
        ipv6: v6.into_iter().collect(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval<T> {
    pub first: T,
    pub after_last: Option<T>,
}

pub fn ipv4_intervals(nets: &[ipnet::Ipv4Net]) -> Vec<Interval<Ipv4Addr>> {
    nets.iter()
        .map(|net| {
            let first = net.network();
            let last = u32::from(net.broadcast());
            Interval {
                first,
                after_last: last.checked_add(1).map(Ipv4Addr::from),
            }
        })
        .collect()
}

pub fn ipv6_intervals(nets: &[ipnet::Ipv6Net]) -> Vec<Interval<Ipv6Addr>> {
    nets.iter()
        .map(|net| {
            let first = net.network();
            let host_bits = 128 - net.prefix_len();
            let base = u128::from(first);
            let last = if host_bits == 128 {
                u128::MAX
            } else {
                base | ((1u128 << host_bits) - 1)
            };
            Interval {
                first,
                after_last: last.checked_add(1).map(Ipv6Addr::from),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_mixed_lists_and_ignores_comments() {
        let got = parse(Cursor::new(
            "# generated at now\n10.0.0.7/24\n\n2001:db8::1/32\n10.0.0.0/24\n",
        ))
        .unwrap();
        assert_eq!(got.ipv4, vec!["10.0.0.0/24".parse().unwrap()]);
        assert_eq!(got.ipv6, vec!["2001:db8::/32".parse().unwrap()]);
    }

    #[test]
    fn rejects_the_whole_file_on_one_bad_line() {
        let err = parse(Cursor::new("10.0.0.0/8\nnot-an-address\n")).unwrap_err();
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn calculates_interval_markers_including_address_space_end() {
        let nets = vec!["255.255.255.0/24".parse().unwrap()];
        assert_eq!(ipv4_intervals(&nets)[0].after_last, None);
        let nets = vec!["10.0.0.0/24".parse().unwrap()];
        assert_eq!(
            ipv4_intervals(&nets)[0].after_last,
            Some("10.0.1.0".parse().unwrap())
        );
    }
}
