#![no_std]

pub const LAYOUT_VERSION: u32 = 1;
pub const SLOT_COUNT: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Control {
    pub layout_version: u32,
    pub active_slot: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Control {}
