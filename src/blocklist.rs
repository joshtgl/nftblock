use anyhow::Result;
use ipnet::IpNet;
use std::{
    io::BufRead,
    net::{Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressInterval {
    V4 {
        first: Ipv4Addr,
        after_last: Option<Ipv4Addr>,
    },
    V6 {
        first: Ipv6Addr,
        after_last: Option<Ipv6Addr>,
    },
}

impl AddressInterval {
    pub fn boundary_elements(self) -> usize {
        match self {
            Self::V4 { after_last, .. } => 1 + usize::from(after_last.is_some()),
            Self::V6 { after_last, .. } => 1 + usize::from(after_last.is_some()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPrefix {
    V4 { address: Ipv4Addr, prefix_len: u8 },
    V6 { address: Ipv6Addr, prefix_len: u8 },
}

/// Decompose an inclusive address interval into the smallest set of CIDR prefixes.
pub fn interval_prefixes(interval: AddressInterval) -> Vec<AddressPrefix> {
    match interval {
        AddressInterval::V4 { first, after_last } => {
            let mut start = u32::from(first);
            let end = after_last.map_or(u32::MAX, |value| u32::from(value) - 1);
            let mut out = Vec::new();
            loop {
                let alignment = if start == 0 {
                    32
                } else {
                    start.trailing_zeros()
                };
                let remaining = u64::from(end) - u64::from(start) + 1;
                let fit = 63 - remaining.leading_zeros();
                let host_bits = alignment.min(fit);
                out.push(AddressPrefix::V4 {
                    address: Ipv4Addr::from(start),
                    prefix_len: (32 - host_bits) as u8,
                });
                let size = 1u64 << host_bits;
                let next = u64::from(start) + size;
                if next > u64::from(end) {
                    break;
                }
                start = next as u32;
            }
            out
        }
        AddressInterval::V6 { first, after_last } => {
            let mut start = u128::from(first);
            let end = after_last.map_or(u128::MAX, |value| u128::from(value) - 1);
            let mut out = Vec::new();
            loop {
                if start == 0 && end == u128::MAX {
                    out.push(AddressPrefix::V6 {
                        address: Ipv6Addr::UNSPECIFIED,
                        prefix_len: 0,
                    });
                    break;
                }
                let alignment = if start == 0 {
                    128
                } else {
                    start.trailing_zeros()
                };
                let remaining = end - start + 1;
                let fit = 127 - remaining.leading_zeros();
                let host_bits = alignment.min(fit);
                out.push(AddressPrefix::V6 {
                    address: Ipv6Addr::from(start),
                    prefix_len: (128 - host_bits) as u8,
                });
                let Some(next) = start.checked_add(1u128 << host_bits) else {
                    break;
                };
                if next > end {
                    break;
                }
                start = next;
            }
            out
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamStats {
    pub cidrs: u64,
    pub ipv4_intervals: u64,
    pub ipv6_intervals: u64,
    pub ipv4_boundaries: u64,
    pub ipv6_boundaries: u64,
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
    #[error("non-canonical blocklist at line {line}: {text:?}: {reason}")]
    NonCanonical {
        line: usize,
        text: String,
        reason: &'static str,
    },
}

#[derive(Clone, Copy)]
enum Pending {
    V4 { first: u32, last: u32 },
    V6 { first: u128, last: u128 },
}

fn flush_pending(
    pending: &mut Option<Pending>,
    chunk: &mut Vec<AddressInterval>,
    chunk_boundaries: &mut usize,
    limit: usize,
    stats: &mut StreamStats,
    emit: &mut impl FnMut(&[AddressInterval]) -> Result<()>,
) -> Result<()> {
    let Some(value) = pending.take() else {
        return Ok(());
    };
    let interval = match value {
        Pending::V4 { first, last } => AddressInterval::V4 {
            first: Ipv4Addr::from(first),
            after_last: last.checked_add(1).map(Ipv4Addr::from),
        },
        Pending::V6 { first, last } => AddressInterval::V6 {
            first: Ipv6Addr::from(first),
            after_last: last.checked_add(1).map(Ipv6Addr::from),
        },
    };
    let elements = interval.boundary_elements();
    if !chunk.is_empty() && *chunk_boundaries + elements > limit {
        emit(chunk)?;
        chunk.clear();
        *chunk_boundaries = 0;
    }
    chunk.push(interval);
    *chunk_boundaries += elements;
    match interval {
        AddressInterval::V4 { .. } => {
            stats.ipv4_intervals += 1;
            stats.ipv4_boundaries += elements as u64;
        }
        AddressInterval::V6 { .. } => {
            stats.ipv6_intervals += 1;
            stats.ipv6_boundaries += elements as u64;
        }
    }
    if *chunk_boundaries >= limit {
        emit(chunk)?;
        chunk.clear();
        *chunk_boundaries = 0;
    }
    Ok(())
}

/// Parse canonical Blockmerge output and emit complete intervals in bounded chunks.
pub fn stream_chunks(
    reader: impl BufRead,
    max_boundary_elements: usize,
    mut emit: impl FnMut(&[AddressInterval]) -> Result<()>,
) -> Result<StreamStats> {
    assert!(max_boundary_elements > 0);
    let mut stats = StreamStats::default();
    let mut chunk = Vec::new();
    let mut chunk_boundaries = 0usize;
    let mut pending: Option<Pending> = None;
    let mut seen_ipv6 = false;

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
        let net = value
            .parse::<IpNet>()
            .map_err(|source| ParseError::Invalid {
                line: number,
                text: value.to_owned(),
                source,
            })?;
        if net != net.trunc() {
            return Err(ParseError::NonCanonical {
                line: number,
                text: value.to_owned(),
                reason: "CIDR has host bits set",
            }
            .into());
        }
        stats.cidrs += 1;
        match net {
            IpNet::V4(net) => {
                if seen_ipv6 {
                    return Err(ParseError::NonCanonical {
                        line: number,
                        text: value.to_owned(),
                        reason: "IPv4 CIDR appears after IPv6",
                    }
                    .into());
                }
                let (first, last) = (u32::from(net.network()), u32::from(net.broadcast()));
                match pending {
                    Some(Pending::V4 {
                        first: old_first,
                        last: old_last,
                    }) => {
                        if first <= old_last {
                            return Err(ParseError::NonCanonical {
                                line: number,
                                text: value.to_owned(),
                                reason: "CIDRs are duplicated, overlapping, or out of order",
                            }
                            .into());
                        }
                        if old_last.checked_add(1) == Some(first) {
                            pending = Some(Pending::V4 {
                                first: old_first,
                                last,
                            });
                        } else {
                            flush_pending(
                                &mut pending,
                                &mut chunk,
                                &mut chunk_boundaries,
                                max_boundary_elements,
                                &mut stats,
                                &mut emit,
                            )?;
                            pending = Some(Pending::V4 { first, last });
                        }
                    }
                    None => pending = Some(Pending::V4 { first, last }),
                    Some(Pending::V6 { .. }) => unreachable!(),
                }
            }
            IpNet::V6(net) => {
                if !seen_ipv6 {
                    flush_pending(
                        &mut pending,
                        &mut chunk,
                        &mut chunk_boundaries,
                        max_boundary_elements,
                        &mut stats,
                        &mut emit,
                    )?;
                    if !chunk.is_empty() {
                        emit(&chunk)?;
                        chunk.clear();
                        chunk_boundaries = 0;
                    }
                    seen_ipv6 = true;
                }
                let first = u128::from(net.network());
                let host_bits = 128 - u32::from(net.prefix_len());
                let last = if host_bits == 128 {
                    u128::MAX
                } else {
                    first | ((1u128 << host_bits) - 1)
                };
                match pending {
                    Some(Pending::V6 {
                        first: old_first,
                        last: old_last,
                    }) => {
                        if first <= old_last {
                            return Err(ParseError::NonCanonical {
                                line: number,
                                text: value.to_owned(),
                                reason: "CIDRs are duplicated, overlapping, or out of order",
                            }
                            .into());
                        }
                        if old_last.checked_add(1) == Some(first) {
                            pending = Some(Pending::V6 {
                                first: old_first,
                                last,
                            });
                        } else {
                            flush_pending(
                                &mut pending,
                                &mut chunk,
                                &mut chunk_boundaries,
                                max_boundary_elements,
                                &mut stats,
                                &mut emit,
                            )?;
                            pending = Some(Pending::V6 { first, last });
                        }
                    }
                    None => pending = Some(Pending::V6 { first, last }),
                    Some(Pending::V4 { .. }) => unreachable!(),
                }
            }
        }
    }
    flush_pending(
        &mut pending,
        &mut chunk,
        &mut chunk_boundaries,
        max_boundary_elements,
        &mut stats,
        &mut emit,
    )?;
    if !chunk.is_empty() {
        emit(&chunk)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(text: &str, limit: usize) -> Result<(Vec<Vec<AddressInterval>>, StreamStats)> {
        let mut chunks = Vec::new();
        let stats = stream_chunks(Cursor::new(text), limit, |chunk| {
            chunks.push(chunk.to_vec());
            Ok(())
        })?;
        Ok((chunks, stats))
    }

    #[test]
    fn streams_canonical_mixed_lists_and_coalesces_adjacency() {
        let (chunks, stats) = parse(
            "# generated\n10.0.0.0/25\n10.0.0.128/25\n2001:db8::/127\n",
            100,
        )
        .unwrap();
        assert_eq!(stats.cidrs, 3);
        assert_eq!(stats.ipv4_intervals, 1);
        assert_eq!(stats.ipv6_intervals, 1);
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0],
            vec![AddressInterval::V4 {
                first: "10.0.0.0".parse().unwrap(),
                after_last: Some("10.0.1.0".parse().unwrap()),
            }]
        );
    }

    #[test]
    fn respects_boundary_element_limit() {
        let (chunks, _) = parse("10.0.0.0/32\n10.0.0.2/32\n10.0.0.4/32\n", 2).unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|chunk| {
            chunk
                .iter()
                .map(|interval| interval.boundary_elements())
                .sum::<usize>()
                <= 2
        }));
    }

    #[test]
    fn rejects_noncanonical_input() {
        for (text, line) in [
            ("10.0.0.7/24\n", 1),
            ("10.0.0.2/32\n10.0.0.0/32\n", 2),
            ("10.0.0.0/32\n10.0.0.0/32\n", 2),
            ("2001:db8::/128\n10.0.0.0/32\n", 2),
        ] {
            let error = parse(text, 100).unwrap_err().to_string();
            assert!(error.contains(&format!("line {line}")), "{error}");
        }
    }

    #[test]
    fn handles_address_space_end_with_one_boundary() {
        let (chunks, stats) = parse("255.255.255.255/32\n", 1).unwrap();
        assert_eq!(stats.ipv4_intervals, 1);
        assert_eq!(stats.ipv4_boundaries, 1);
        assert_eq!(chunks[0][0].boundary_elements(), 1);
    }

    #[test]
    fn decomposes_intervals_into_minimal_prefixes() {
        assert_eq!(
            interval_prefixes(AddressInterval::V4 {
                first: "10.0.0.0".parse().unwrap(),
                after_last: Some("10.0.1.0".parse().unwrap()),
            }),
            [AddressPrefix::V4 {
                address: "10.0.0.0".parse().unwrap(),
                prefix_len: 24
            }]
        );
        assert_eq!(
            interval_prefixes(AddressInterval::V6 {
                first: Ipv6Addr::UNSPECIFIED,
                after_last: None,
            }),
            [AddressPrefix::V6 {
                address: Ipv6Addr::UNSPECIFIED,
                prefix_len: 0
            }]
        );
    }
}
