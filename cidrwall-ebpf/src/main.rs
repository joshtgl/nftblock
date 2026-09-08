#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LpmTrie},
    programs::XdpContext,
};
use cidrwall_common::Control;

#[map]
static CONTROL: Array<Control> = Array::pinned(1, 0);
#[map]
static IPV4_A: LpmTrie<[u8; 4], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static IPV4_B: LpmTrie<[u8; 4], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static IPV6_A: LpmTrie<[u8; 16], u8> = LpmTrie::pinned(5_000_000, 0);
#[map]
static IPV6_B: LpmTrie<[u8; 16], u8> = LpmTrie::pinned(5_000_000, 0);

#[xdp]
pub fn cidrwall(ctx: XdpContext) -> u32 {
    try_cidrwall(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

fn try_cidrwall(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let end = ctx.data_end();
    if data + 14 > end {
        return Ok(xdp_action::XDP_PASS);
    }
    let mut offset = 14usize;
    let mut ether_type = read_be_u16(data, end, 12)?;
    for _ in 0..2 {
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            break;
        }
        ether_type = read_be_u16(data, end, offset + 2)?;
        offset += 4;
    }
    let slot = CONTROL.get(0).map_or(0, |value| value.active_slot);
    let blocked = match ether_type {
        0x0800 => {
            if data + offset + 20 > end {
                return Ok(xdp_action::XDP_PASS);
            }
            let version_ihl = read_u8(data, end, offset)?;
            if version_ihl >> 4 != 4 || version_ihl & 0x0f < 5 {
                return Ok(xdp_action::XDP_PASS);
            }
            let address = read_array::<4>(data, end, offset + 12)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
            if slot == 0 {
                IPV4_A.get(&key)
            } else {
                IPV4_B.get(&key)
            }
            .is_some()
        }
        0x86dd => {
            if data + offset + 40 > end || read_u8(data, end, offset)? >> 4 != 6 {
                return Ok(xdp_action::XDP_PASS);
            }
            let address = read_array::<16>(data, end, offset + 8)?;
            let key = aya_ebpf::maps::lpm_trie::Key::new(128, address);
            if slot == 0 {
                IPV6_A.get(&key)
            } else {
                IPV6_B.get(&key)
            }
            .is_some()
        }
        _ => false,
    };
    Ok(if blocked {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    })
}

fn read_u8(data: usize, end: usize, offset: usize) -> Result<u8, ()> {
    if data + offset + 1 > end {
        return Err(());
    }
    Ok(unsafe { *((data + offset) as *const u8) })
}

fn read_be_u16(data: usize, end: usize, offset: usize) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(read_array::<2>(data, end, offset)?))
}

fn read_array<const N: usize>(data: usize, end: usize, offset: usize) -> Result<[u8; N], ()> {
    if data + offset + N > end {
        return Err(());
    }
    let mut value = [0; N];
    let mut index = 0;
    while index < N {
        value[index] = unsafe { *((data + offset + index) as *const u8) };
        index += 1;
    }
    Ok(value)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
