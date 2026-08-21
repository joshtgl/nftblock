//! Small, auditable wrappers around the libnftnl operations not exposed by `nftnl`.
//!
//! All project-owned unsafe operations live in this module. The safe API maintains these
//! invariants:
//! - allocated C objects are owned by exactly one RAII guard until ownership is transferred;
//! - byte buffers passed to libmnl are initialized, suitably aligned, and bounds checked;
//! - pointers borrowed from a flowtable are copied before that flowtable is freed;
//! - objects referenced by serialized netlink messages outlive serialization.
//!
//! Upstreaming these missing safe operations to `nftnl` remains a follow-up. These local
//! wrappers can be removed as equivalent APIs become available there.

use nftnl::{
    Chain, MsgType, NlMsg, ProtoFamily, Rule, Table,
    expr::Expression,
    nftnl_sys::{self as sys, libc},
    set::{Set, SetKey},
};
use std::{
    ffi::{CStr, CString, c_void},
    io,
    mem::{align_of, size_of},
    os::raw::c_char,
    ptr::NonNull,
};

const NFT_MSG_GETFLOWTABLE: u16 = 23;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_GETSET: u16 = 10;
const MAX_FLOWTABLE_DEVICES: usize = 4096;

/// Releases one kind of uniquely owned C allocation.
///
/// # Safety
///
/// Implementations must accept every live pointer paired with them by `OwnedPtr`, release that
/// allocation exactly once, and never retain the pointer after returning.
unsafe trait Deallocator<T> {
    unsafe fn deallocate(&mut self, pointer: NonNull<T>);
}

/// Owns a non-null C allocation until it is dropped or explicitly transferred.
struct OwnedPtr<T, D: Deallocator<T>> {
    pointer: Option<NonNull<T>>,
    deallocator: D,
}

impl<T, D: Deallocator<T>> OwnedPtr<T, D> {
    /// Takes ownership of an allocation returned by C.
    ///
    /// # Safety
    ///
    /// A non-null `pointer` must be uniquely owned, live, and compatible with `deallocator`.
    unsafe fn from_alloc(
        pointer: *mut T,
        deallocator: D,
        object: &'static str,
    ) -> io::Result<Self> {
        let pointer = NonNull::new(pointer).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("libnftnl {object} allocation returned null"),
            )
        })?;
        Ok(Self {
            pointer: Some(pointer),
            deallocator,
        })
    }

    fn pointer(&self) -> NonNull<T> {
        self.pointer
            .expect("C allocation ownership was transferred")
    }

    fn into_non_null(mut self) -> NonNull<T> {
        self.pointer
            .take()
            .expect("C allocation ownership was transferred")
    }
}

impl<T, D: Deallocator<T>> Drop for OwnedPtr<T, D> {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer.take() {
            // SAFETY: A pointer remaining in the guard is live, uniquely owned, and paired with
            // this deallocator by `from_alloc`.
            unsafe { self.deallocator.deallocate(pointer) };
        }
    }
}

/// An nftables named interval set with safe interval-element construction.
pub(super) struct IntervalSet<'table, K> {
    inner: Set<'table, K>,
}

impl<'table, K: SetKey> IntervalSet<'table, K> {
    pub(super) fn new(name: &CStr, id: u32, table: &'table Table) -> Self {
        let inner = Set::new_named(name, id, table, ProtoFamily::Inet);
        // SAFETY: `inner` owns a valid libnftnl set pointer for the duration of this call.
        unsafe {
            sys::nftnl_set_set_u32(
                inner.as_ptr().as_ptr(),
                sys::NFTNL_SET_FLAGS as u16,
                libc::NFT_SET_INTERVAL as u32,
            )
        };
        Self { inner }
    }

    /// Select a named set created by an earlier transaction.
    pub(super) fn existing(name: &CStr, table: &'table Table) -> Self {
        Self::new(name, 0, table)
    }

    pub(super) fn add_range(&mut self, first: &K, after_last: Option<&K>) -> io::Result<()> {
        SetElement::new()?.set_key(first)?.attach(&mut self.inner);
        if let Some(after_last) = after_last {
            SetElement::new()?
                .set_key(after_last)?
                .mark_interval_end()
                .attach(&mut self.inner);
        }
        Ok(())
    }

    pub(super) fn as_set(&self) -> &Set<'table, K> {
        &self.inner
    }
}

pub(super) struct ExistingElements<T>(T);
impl<T> ExistingElements<T> {
    pub(super) fn new(value: T) -> Self {
        Self(value)
    }
}

// SAFETY: the inner serializer satisfies NlMsg; removing one complete, aligned top-level
// attribute only shortens that already bounded message.
unsafe impl<T: NlMsg> NlMsg for ExistingElements<T> {
    unsafe fn write(&self, buffer: *mut c_void, seq: u32, message_type: MsgType) {
        // SAFETY: inherited directly from the outer NlMsg call.
        unsafe { self.0.write(buffer, seq, message_type) };
        // SAFETY: the inner call initialized a bounded netlink message in `buffer`.
        unsafe { remove_top_level_attribute(buffer, 4) };
    }
}

pub(super) struct ExistingSetMessage<'set, 'table, K>(&'set Set<'table, K>);
impl<'set, 'table, K> ExistingSetMessage<'set, 'table, K> {
    pub(super) fn new(set: &'set Set<'table, K>) -> Self {
        Self(set)
    }
}

// SAFETY: the inner serializer satisfies NlMsg; removing the transaction-local ID leaves a
// persistent table/name set selector.
unsafe impl<K> NlMsg for ExistingSetMessage<'_, '_, K> {
    unsafe fn write(&self, buffer: *mut c_void, seq: u32, message_type: MsgType) {
        // SAFETY: inherited directly from the outer NlMsg call.
        unsafe { self.0.write(buffer, seq, message_type) };
        // SAFETY: the inner call initialized a bounded netlink message in `buffer`.
        unsafe { remove_top_level_attribute(buffer, 10) };
    }
}

unsafe fn remove_top_level_attribute(buffer: *mut c_void, target: u16) {
    const NFGENMSG_LEN: usize = 4;
    const NLA_HEADER_LEN: usize = 4;
    const NLA_TYPE_MASK: u16 = 0x3fff;
    let header = buffer.cast::<libc::nlmsghdr>();
    // SAFETY: guaranteed by this helper's contract.
    let len = unsafe { (*header).nlmsg_len as usize };
    // SAFETY: guaranteed by this helper's contract.
    let bytes = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), len) };
    let mut offset = size_of::<libc::nlmsghdr>() + NFGENMSG_LEN;
    while offset + NLA_HEADER_LEN <= len {
        let attr_len =
            u16::from_ne_bytes(bytes[offset..offset + 2].try_into().expect("NLA header")) as usize;
        if attr_len < NLA_HEADER_LEN || offset + attr_len > len {
            return;
        }
        let attr_type =
            u16::from_ne_bytes(bytes[offset + 2..offset + 4].try_into().expect("NLA type"))
                & NLA_TYPE_MASK;
        let aligned = attr_len.next_multiple_of(4);
        if offset + aligned > len {
            return;
        }
        if attr_type == target {
            bytes.copy_within(offset + aligned..len, offset);
            // SAFETY: the header remains at the start of the same live buffer.
            unsafe { (*header).nlmsg_len = (len - aligned) as u32 };
            return;
        }
        offset += aligned;
    }
}

/// Lookup expression for a named set that was created by an earlier transaction.
pub(super) struct NamedLookup(CString);

impl NamedLookup {
    pub(super) fn new(name: &CStr) -> Self {
        Self(name.to_owned())
    }
}

impl Expression for NamedLookup {
    fn to_expr(&self, _rule: &Rule) -> NonNull<sys::nftnl_expr> {
        // SAFETY: allocation has no preconditions.
        let expression = unsafe { sys::nftnl_expr_alloc(c"lookup".as_ptr()) };
        let expression = NonNull::new(expression).unwrap_or_else(|| std::process::abort());
        // SAFETY: the expression is live and uniquely owned; this initializes its source register.
        unsafe {
            sys::nftnl_expr_set_u32(
                expression.as_ptr(),
                sys::NFTNL_EXPR_LOOKUP_SREG as u16,
                libc::NFT_REG_1 as u32,
            );
        }
        // SAFETY: the expression and name are live, and libnftnl copies the name. Omitting SET_ID
        // deliberately selects the persistent set by name.
        unsafe {
            sys::nftnl_expr_set_str(
                expression.as_ptr(),
                sys::NFTNL_EXPR_LOOKUP_SET as u16,
                self.0.as_ptr(),
            );
        }
        expression
    }
}

/// Owns a set element until libnftnl takes ownership through `nftnl_set_elem_add`.
struct FreeSetElement;

// SAFETY: `nftnl_set_elem_free` is the matching release operation for pointers returned by
// `nftnl_set_elem_alloc`.
unsafe impl Deallocator<sys::nftnl_set_elem> for FreeSetElement {
    unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_set_elem>) {
        // SAFETY: Guaranteed by the `Deallocator` contract and the allocation site below.
        unsafe { sys::nftnl_set_elem_free(pointer.as_ptr()) };
    }
}

struct SetElement(OwnedPtr<sys::nftnl_set_elem, FreeSetElement>);

impl SetElement {
    fn new() -> io::Result<Self> {
        // SAFETY: Allocation has no preconditions and returns either null or a uniquely owned
        // element pointer.
        let pointer = unsafe { sys::nftnl_set_elem_alloc() };
        // SAFETY: A non-null result is uniquely owned and must be released with
        // `nftnl_set_elem_free` until attached to a set.
        let pointer = unsafe { OwnedPtr::from_alloc(pointer, FreeSetElement, "set element") }?;
        Ok(Self(pointer))
    }

    fn set_key<K: SetKey>(self, key: &K) -> io::Result<Self> {
        let data = key.data();
        let data_len = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "set key is too large"))?;
        // SAFETY: The element is still owned by `self`; `data` remains alive for the call, and
        // libnftnl copies an input buffer of exactly `data_len` bytes.
        let result = unsafe {
            sys::nftnl_set_elem_set(
                self.pointer().as_ptr(),
                sys::NFTNL_SET_ELEM_KEY as u16,
                data.as_ptr().cast::<c_void>(),
                data_len,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(self)
    }

    fn mark_interval_end(self) -> Self {
        // SAFETY: The element is valid and uniquely owned by `self`.
        unsafe {
            sys::nftnl_set_elem_set_u32(
                self.pointer().as_ptr(),
                sys::NFTNL_SET_ELEM_FLAGS as u16,
                libc::NFT_SET_ELEM_INTERVAL_END as u32,
            )
        };
        self
    }

    fn attach<K>(self, set: &mut Set<'_, K>) {
        let pointer = self.0.into_non_null();
        // SAFETY: Both pointers are valid and uniquely mutable. Per libnftnl's ownership
        // contract, the set takes ownership of `pointer`; `into_non_null` disarmed the guard.
        unsafe { sys::nftnl_set_elem_add(set.as_ptr().as_ptr(), pointer.as_ptr()) };
    }

    fn pointer(&self) -> NonNull<sys::nftnl_set_elem> {
        self.0.pointer()
    }
}

/// A rule deletion selector without a handle flushes every rule in the chain.
pub(super) struct RuleFlush<'chain, 'table> {
    chain: &'chain Chain<'table>,
}

impl<'chain, 'table> RuleFlush<'chain, 'table> {
    pub(super) fn new(chain: &'chain Chain<'table>) -> Self {
        Self { chain }
    }
}

// SAFETY: serialization writes one bounded rule-delete message and all borrowed objects outlive it.
#[allow(clippy::multiple_unsafe_ops_per_block)]
unsafe impl NlMsg for RuleFlush<'_, '_> {
    unsafe fn write(&self, buffer: *mut c_void, seq: u32, _msg_type: MsgType) {
        // SAFETY: allocation has no preconditions and is checked before use.
        let rule = unsafe { sys::nftnl_rule_alloc() };
        if rule.is_null() {
            std::process::abort();
        }
        // SAFETY: `rule` is live and uniquely owned, chain strings remain live through
        // serialization, and the NlMsg contract provides a sufficiently large output buffer.
        unsafe {
            sys::nftnl_rule_set_u32(
                rule,
                sys::NFTNL_RULE_FAMILY as u16,
                self.chain.get_table().get_family() as u32,
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_TABLE as u16,
                self.chain.get_table().get_name().as_ptr(),
            );
            sys::nftnl_rule_set_str(
                rule,
                sys::NFTNL_RULE_CHAIN as u16,
                self.chain.get_name().as_ptr(),
            );
            let header = sys::nftnl_nlmsg_build_hdr(
                buffer.cast::<c_char>(),
                libc::NFT_MSG_DELRULE as u16,
                ProtoFamily::Inet as u16,
                libc::NLM_F_ACK as u16,
                seq,
            );
            sys::nftnl_rule_nlmsg_build_payload(header, rule);
            sys::nftnl_rule_free(rule);
        }
    }
}

struct FreeTable;
// SAFETY: `nftnl_table_free` matches pointers returned by `nftnl_table_alloc`.
unsafe impl Deallocator<sys::nftnl_table> for FreeTable {
    unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_table>) {
        // SAFETY: guaranteed by the Deallocator contract.
        unsafe { sys::nftnl_table_free(pointer.as_ptr()) };
    }
}

pub(super) struct TableInfo(OwnedPtr<sys::nftnl_table, FreeTable>);
impl TableInfo {
    pub(super) fn parse(message: &libc::nlmsghdr) -> io::Result<Self> {
        // SAFETY: allocation has no preconditions.
        let pointer = unsafe { sys::nftnl_table_alloc() };
        // SAFETY: a non-null pointer is uniquely owned and paired with FreeTable.
        let pointer = unsafe { OwnedPtr::from_alloc(pointer, FreeTable, "table") }?;
        let value = Self(pointer);
        // SAFETY: the netlink message and destination table are live and bounded.
        if unsafe { sys::nftnl_table_nlmsg_parse(message, value.0.pointer().as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }
    pub(super) fn name(&self) -> io::Result<String> {
        // SAFETY: the parsed table remains live for this borrowed attribute lookup.
        let value = unsafe {
            sys::nftnl_table_get_str(self.0.pointer().as_ptr(), sys::NFTNL_TABLE_NAME as u16)
        };
        if value.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "table has no name",
            ));
        }
        // SAFETY: libnftnl returns a NUL-terminated string owned by the live table.
        Ok(unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned())
    }
}

struct FreeSet;
// SAFETY: `nftnl_set_free` matches pointers returned by `nftnl_set_alloc`.
unsafe impl Deallocator<sys::nftnl_set> for FreeSet {
    unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_set>) {
        // SAFETY: guaranteed by the Deallocator contract.
        unsafe { sys::nftnl_set_free(pointer.as_ptr()) };
    }
}

pub(super) struct SetInfo(OwnedPtr<sys::nftnl_set, FreeSet>);
impl SetInfo {
    pub(super) fn parse(message: &libc::nlmsghdr) -> io::Result<Self> {
        // SAFETY: allocation has no preconditions.
        let pointer = unsafe { sys::nftnl_set_alloc() };
        // SAFETY: a non-null pointer is uniquely owned and paired with FreeSet.
        let pointer = unsafe { OwnedPtr::from_alloc(pointer, FreeSet, "set") }?;
        let value = Self(pointer);
        // SAFETY: the netlink message and destination set are live and bounded.
        if unsafe { sys::nftnl_set_nlmsg_parse(message, value.0.pointer().as_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }
    fn string(&self, attr: u32, label: &'static str) -> io::Result<String> {
        // SAFETY: the parsed set remains live for this borrowed attribute lookup.
        let value = unsafe { sys::nftnl_set_get_str(self.0.pointer().as_ptr(), attr as u16) };
        if value.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("set has no {label}"),
            ));
        }
        // SAFETY: libnftnl returns a NUL-terminated string owned by the live set.
        Ok(unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned())
    }
    pub(super) fn table(&self) -> io::Result<String> {
        self.string(sys::NFTNL_SET_TABLE, "table")
    }
    pub(super) fn name(&self) -> io::Result<String> {
        self.string(sys::NFTNL_SET_NAME, "name")
    }
    pub(super) fn count(message: &libc::nlmsghdr) -> Option<u32> {
        const NFGENMSG_LEN: usize = 4;
        const NLA_HEADER_LEN: usize = 4;
        const NLA_TYPE_MASK: u16 = 0x3fff;
        const NFTA_SET_COUNT: u16 = 20;
        let len = message.nlmsg_len as usize;
        if len < size_of::<libc::nlmsghdr>() + NFGENMSG_LEN {
            return None;
        }
        // SAFETY: `nlmsg_len` bounds the live kernel-provided message containing this header.
        let bytes = unsafe {
            std::slice::from_raw_parts((message as *const libc::nlmsghdr).cast::<u8>(), len)
        };
        let mut offset = size_of::<libc::nlmsghdr>() + NFGENMSG_LEN;
        while offset + NLA_HEADER_LEN <= bytes.len() {
            let attr_len = u16::from_ne_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
            let attr_type =
                u16::from_ne_bytes(bytes[offset + 2..offset + 4].try_into().ok()?) & NLA_TYPE_MASK;
            if attr_len < NLA_HEADER_LEN || offset + attr_len > bytes.len() {
                return None;
            }
            if attr_type == NFTA_SET_COUNT && attr_len >= NLA_HEADER_LEN + 4 {
                return Some(u32::from_be_bytes(
                    bytes[offset + 4..offset + 8].try_into().ok()?,
                ));
            }
            offset += attr_len.next_multiple_of(4);
        }
        None
    }
}

/// A parsed flowtable whose borrowed C data is copied before this guard is dropped.
struct FreeFlowtable;

// SAFETY: `nftnl_flowtable_free` is the matching release operation for pointers returned by
// `nftnl_flowtable_alloc`.
unsafe impl Deallocator<sys::nftnl_flowtable> for FreeFlowtable {
    unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_flowtable>) {
        // SAFETY: Guaranteed by the `Deallocator` contract and the allocation site below.
        unsafe { sys::nftnl_flowtable_free(pointer.as_ptr()) };
    }
}

pub(super) struct Flowtable(OwnedPtr<sys::nftnl_flowtable, FreeFlowtable>);

impl Flowtable {
    pub(super) fn parse(message: &libc::nlmsghdr) -> io::Result<Self> {
        // SAFETY: Allocation has no preconditions and returns a uniquely owned pointer or null.
        let pointer = unsafe { sys::nftnl_flowtable_alloc() };
        // SAFETY: A non-null result is uniquely owned and paired with `nftnl_flowtable_free`.
        let pointer = unsafe { OwnedPtr::from_alloc(pointer, FreeFlowtable, "flowtable") }?;
        let flowtable = Self(pointer);
        // SAFETY: `message` is validated and supplied by libmnl, while `flowtable` owns a valid
        // mutable destination object.
        let result =
            unsafe { sys::nftnl_flowtable_nlmsg_parse(message, flowtable.0.pointer().as_ptr()) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flowtable)
    }

    pub(super) fn device_names(&self) -> io::Result<Vec<String>> {
        // SAFETY: The flowtable pointer remains valid and immutable for this call.
        let is_set = unsafe {
            sys::nftnl_flowtable_is_set(
                self.0.pointer().as_ptr(),
                sys::NFTNL_FLOWTABLE_DEVICES as u16,
            )
        };
        if !is_set {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "flowtable response has no device array",
            ));
        }
        // SAFETY: The flowtable is valid and the requested attribute was confirmed present.
        let devices = unsafe {
            sys::nftnl_flowtable_get_array(
                self.0.pointer().as_ptr(),
                sys::NFTNL_FLOWTABLE_DEVICES as u16,
            )
        };
        if devices.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "flowtable returned a null device array",
            ));
        }

        let mut names = Vec::new();
        for index in 0..MAX_FLOWTABLE_DEVICES {
            // SAFETY: libnftnl documents this attribute as a null-terminated pointer array. The
            // explicit cap prevents an unbounded scan if that contract is violated.
            let slot = unsafe { devices.add(index) };
            // SAFETY: `slot` is within the documented array up to and including its terminator.
            let device = unsafe { *slot };
            if device.is_null() {
                return Ok(names);
            }
            // SAFETY: Each non-null array entry is documented as a NUL-terminated C string owned
            // by the flowtable and valid until it is freed.
            let name = unsafe { CStr::from_ptr(device) };
            let name = name.to_str().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "flowtable device is not UTF-8")
            })?;
            names.push(name.to_owned());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "flowtable device array is not terminated",
        ))
    }
}

/// Zeroed byte storage with alignment suitable for `nlmsghdr`.
pub(super) struct AlignedNetlinkBuffer {
    words: Vec<u64>,
}

impl AlignedNetlinkBuffer {
    pub(super) fn new(byte_capacity: usize) -> Self {
        assert!(align_of::<u64>() >= align_of::<libc::nlmsghdr>());
        let words = byte_capacity.max(size_of::<libc::nlmsghdr>()).div_ceil(8);
        Self {
            words: vec![0; words],
        }
    }

    pub(super) fn capacity(&self) -> usize {
        self.words.len() * size_of::<u64>()
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        // SAFETY: `u64` has no invalid bit patterns, all storage is initialized, and the returned
        // slice is limited to the allocation's exact byte extent.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.capacity()) }
    }

    pub(super) fn as_bytes_mut(&mut self) -> &mut [u8] {
        let capacity = self.capacity();
        // SAFETY: `u8` has alignment one and no invalid bit patterns; the mutable borrow of `self`
        // guarantees unique access to the initialized allocation.
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast::<u8>(), capacity) }
    }

    pub(super) fn prefix(&self, len: usize) -> io::Result<&[u8]> {
        self.as_bytes().get(..len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "netlink message exceeds its aligned buffer",
            )
        })
    }
}

pub(super) struct NetlinkRequest {
    buffer: AlignedNetlinkBuffer,
    len: usize,
}

impl NetlinkRequest {
    fn dump(message_type: u16, seq: u32) -> io::Result<Self> {
        let mut buffer = AlignedNetlinkBuffer::new(4096);
        // SAFETY: the initialized aligned buffer is large enough for an empty dump request.
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buffer.as_bytes_mut().as_mut_ptr().cast::<c_char>(),
                message_type,
                ProtoFamily::Unspec as u16,
                (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
                seq,
            )
        };
        let header =
            NonNull::new(header).ok_or_else(|| io::Error::other("null dump request header"))?;
        // SAFETY: the header was checked non-null and points into the live request buffer.
        let len = unsafe { header.as_ref().nlmsg_len as usize };
        if len < size_of::<libc::nlmsghdr>() || len > buffer.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid dump request length",
            ));
        }
        Ok(Self { buffer, len })
    }

    pub(super) fn table_dump(seq: u32) -> io::Result<Self> {
        Self::dump(NFT_MSG_GETTABLE, seq)
    }
    pub(super) fn set_dump(seq: u32) -> io::Result<Self> {
        Self::dump(NFT_MSG_GETSET, seq)
    }

    pub(super) fn flowtable_dump(seq: u32) -> io::Result<Self> {
        let mut buffer = AlignedNetlinkBuffer::new(4096);
        // SAFETY: The buffer is initialized, aligned, and large enough for a netlink header and
        // the empty flowtable dump request generated here.
        let header = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buffer.as_bytes_mut().as_mut_ptr().cast::<c_char>(),
                NFT_MSG_GETFLOWTABLE,
                ProtoFamily::Unspec as u16,
                (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
                seq,
            )
        };
        let header = NonNull::new(header)
            .ok_or_else(|| io::Error::other("libnftnl returned a null flowtable request header"))?;
        if !std::ptr::eq(
            header.as_ptr().cast::<u8>().cast_const(),
            buffer.as_bytes().as_ptr(),
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "libnftnl returned a header outside the request buffer",
            ));
        }
        // SAFETY: The header was checked non-null and points to the initialized request buffer.
        let len = unsafe { header.as_ref().nlmsg_len as usize };
        if len < size_of::<libc::nlmsghdr>() || len > buffer.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "libnftnl returned an invalid request length",
            ));
        }
        Ok(Self { buffer, len })
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        self.buffer
            .prefix(self.len)
            .expect("validated netlink request length")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nftnl::MsgType;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        ptr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    const NFT_MSG_NEWFLOWTABLE: u16 = 22;

    struct CountingDeallocator(Arc<AtomicUsize>);

    // SAFETY: Test pointers are produced by `Box::into_raw` and transferred to at most one guard.
    unsafe impl Deallocator<u8> for CountingDeallocator {
        unsafe fn deallocate(&mut self, pointer: NonNull<u8>) {
            self.0.fetch_add(1, Ordering::SeqCst);
            // SAFETY: Guaranteed by this test deallocator's contract and its allocation sites.
            drop(unsafe { Box::from_raw(pointer.as_ptr()) });
        }
    }

    struct FreeSet;

    // SAFETY: `nftnl_set_free` matches `nftnl_set_alloc`.
    unsafe impl Deallocator<sys::nftnl_set> for FreeSet {
        unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_set>) {
            // SAFETY: Guaranteed by the test fixture's allocation site.
            unsafe { sys::nftnl_set_free(pointer.as_ptr()) };
        }
    }

    struct FreeSetIterator;

    // SAFETY: `nftnl_set_elems_iter_destroy` matches `nftnl_set_elems_iter_create`.
    unsafe impl Deallocator<sys::nftnl_set_elems_iter> for FreeSetIterator {
        unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_set_elems_iter>) {
            // SAFETY: Guaranteed by the test fixture's allocation site.
            unsafe { sys::nftnl_set_elems_iter_destroy(pointer.as_ptr()) };
        }
    }

    struct FreeRule;

    // SAFETY: `nftnl_rule_free` matches `nftnl_rule_alloc`.
    unsafe impl Deallocator<sys::nftnl_rule> for FreeRule {
        unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_rule>) {
            // SAFETY: Guaranteed by the test fixture's allocation site.
            unsafe { sys::nftnl_rule_free(pointer.as_ptr()) };
        }
    }

    struct FreeExpressionIterator;

    // SAFETY: `nftnl_expr_iter_destroy` matches `nftnl_expr_iter_create`.
    unsafe impl Deallocator<sys::nftnl_expr_iter> for FreeExpressionIterator {
        unsafe fn deallocate(&mut self, pointer: NonNull<sys::nftnl_expr_iter>) {
            // SAFETY: Guaranteed by the test fixture's allocation site.
            unsafe { sys::nftnl_expr_iter_destroy(pointer.as_ptr()) };
        }
    }

    fn allocate_test_set() -> OwnedPtr<sys::nftnl_set, FreeSet> {
        // SAFETY: Allocation has no preconditions.
        let pointer = unsafe { sys::nftnl_set_alloc() };
        // SAFETY: A non-null result is uniquely owned and paired with `nftnl_set_free`.
        unsafe { OwnedPtr::from_alloc(pointer, FreeSet, "test set") }.unwrap()
    }

    fn allocate_test_rule() -> OwnedPtr<sys::nftnl_rule, FreeRule> {
        // SAFETY: Allocation has no preconditions.
        let pointer = unsafe { sys::nftnl_rule_alloc() };
        // SAFETY: A non-null result is uniquely owned and paired with `nftnl_rule_free`.
        unsafe { OwnedPtr::from_alloc(pointer, FreeRule, "test rule") }.unwrap()
    }

    fn serialize<T: NlMsg>(message: &T, msg_type: MsgType, seq: u32) -> NetlinkRequest {
        let mut buffer = AlignedNetlinkBuffer::new(nftnl::nft_nlmsg_maxsize() as usize);
        // SAFETY: The aligned buffer has the capacity required by the `NlMsg` contract.
        unsafe {
            message.write(
                buffer.as_bytes_mut().as_mut_ptr().cast::<c_void>(),
                seq,
                msg_type,
            )
        };
        let len = header(buffer.as_bytes()).nlmsg_len as usize;
        assert!(len >= size_of::<libc::nlmsghdr>());
        assert!(len <= buffer.capacity());
        NetlinkRequest { buffer, len }
    }

    fn header(message: &[u8]) -> &libc::nlmsghdr {
        assert!(message.len() >= size_of::<libc::nlmsghdr>());
        let pointer = message.as_ptr().cast::<libc::nlmsghdr>();
        assert!(pointer.is_aligned());
        // SAFETY: The slice is large enough, suitably aligned, and `nlmsghdr` accepts every bit
        // pattern. Callers retain the backing aligned buffer for the returned borrow.
        unsafe { &*pointer }
    }

    fn nft_message_type(message: u16) -> u16 {
        ((libc::NFNL_SUBSYS_NFTABLES as u16) << 8) | message
    }

    fn top_level_attributes(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
        const NFGENMSG_LEN: usize = 4;
        const NLA_HEADER_LEN: usize = 4;
        const NLA_TYPE_MASK: u16 = 0x3fff;
        let mut attributes = Vec::new();
        let mut offset = size_of::<libc::nlmsghdr>() + NFGENMSG_LEN;
        while offset + NLA_HEADER_LEN <= message.len() {
            let len = u16::from_ne_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
            assert!(len >= NLA_HEADER_LEN);
            assert!(offset + len <= message.len());
            let attribute_type =
                u16::from_ne_bytes(message[offset + 2..offset + 4].try_into().unwrap())
                    & NLA_TYPE_MASK;
            attributes.push((
                attribute_type,
                message[offset + NLA_HEADER_LEN..offset + len].to_vec(),
            ));
            offset += len.next_multiple_of(4);
        }
        assert_eq!(offset, message.len());
        attributes
    }

    fn synthetic_message(attributes: &[(u16, &[u8])]) -> NetlinkRequest {
        const NFGENMSG_LEN: usize = 4;
        const NLA_HEADER_LEN: usize = 4;
        let mut buffer = AlignedNetlinkBuffer::new(4096);
        let mut len = size_of::<libc::nlmsghdr>() + NFGENMSG_LEN;
        for (attribute_type, payload) in attributes {
            let attribute_len = NLA_HEADER_LEN + payload.len();
            let aligned_len = attribute_len.next_multiple_of(4);
            let bytes = buffer.as_bytes_mut();
            bytes[len..len + 2].copy_from_slice(&(attribute_len as u16).to_ne_bytes());
            bytes[len + 2..len + 4].copy_from_slice(&attribute_type.to_ne_bytes());
            bytes[len + NLA_HEADER_LEN..len + attribute_len].copy_from_slice(payload);
            len += aligned_len;
        }
        let header = buffer.as_bytes_mut().as_mut_ptr().cast::<libc::nlmsghdr>();
        // SAFETY: The aligned allocation contains a complete header and all attributes fit in it.
        unsafe { (*header).nlmsg_len = len as u32 };
        NetlinkRequest { buffer, len }
    }

    fn set_message_len(message: &mut NetlinkRequest, len: usize) {
        assert!(len <= message.buffer.capacity());
        let header = message
            .buffer
            .as_bytes_mut()
            .as_mut_ptr()
            .cast::<libc::nlmsghdr>();
        // SAFETY: The buffer is aligned and contains a complete netlink header.
        unsafe { (*header).nlmsg_len = len as u32 };
        message.len = len;
    }

    fn parse_set_definition(target: &OwnedPtr<sys::nftnl_set, FreeSet>, message: &NetlinkRequest) {
        // SAFETY: Both objects are live; the serialized message is aligned, bounded, and remains
        // borrowed for the call.
        let result = unsafe {
            sys::nftnl_set_nlmsg_parse(header(message.as_bytes()), target.pointer().as_ptr())
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
    }

    fn parse_set_elements(target: &OwnedPtr<sys::nftnl_set, FreeSet>, message: &NetlinkRequest) {
        // SAFETY: Both objects are live; the serialized message is aligned, bounded, and remains
        // borrowed for the call.
        let result = unsafe {
            sys::nftnl_set_elems_nlmsg_parse(header(message.as_bytes()), target.pointer().as_ptr())
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
    }

    fn parse_rule(target: &OwnedPtr<sys::nftnl_rule, FreeRule>, message: &NetlinkRequest) {
        // SAFETY: Both objects are live; the serialized message is aligned and bounded.
        let result = unsafe {
            sys::nftnl_rule_nlmsg_parse(header(message.as_bytes()), target.pointer().as_ptr())
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
    }

    fn rule_string(rule: &OwnedPtr<sys::nftnl_rule, FreeRule>, attribute: u32) -> &CStr {
        // SAFETY: The parsed rule is live and the fixture includes this string attribute.
        let pointer = unsafe { sys::nftnl_rule_get_str(rule.pointer().as_ptr(), attribute as u16) };
        assert!(!pointer.is_null());
        // SAFETY: libnftnl owns a NUL-terminated string for the lifetime of `rule`.
        unsafe { CStr::from_ptr(pointer) }
    }

    fn normalize_element_types_for_kernel_reply(message: &mut NetlinkRequest) {
        const NFGENMSG_LEN: usize = 4;
        const NLA_HEADER_LEN: usize = 4;
        const NLA_TYPE_MASK: u16 = 0x3fff;
        const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
        const NFTA_LIST_ELEM: u16 = 1;

        fn read_u16(bytes: &[u8], offset: usize) -> u16 {
            u16::from_ne_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }

        let message_len = message.len;
        let bytes = &mut message.buffer.as_bytes_mut()[..message_len];
        let mut attribute_offset = size_of::<libc::nlmsghdr>() + NFGENMSG_LEN;
        while attribute_offset + NLA_HEADER_LEN <= bytes.len() {
            let attribute_len = read_u16(bytes, attribute_offset) as usize;
            assert!(attribute_len >= NLA_HEADER_LEN);
            assert!(attribute_offset + attribute_len <= bytes.len());
            let attribute_type = read_u16(bytes, attribute_offset + 2) & NLA_TYPE_MASK;
            if attribute_type == NFTA_SET_ELEM_LIST_ELEMENTS {
                let nested_end = attribute_offset + attribute_len;
                let mut element_offset = attribute_offset + NLA_HEADER_LEN;
                while element_offset + NLA_HEADER_LEN <= nested_end {
                    let element_len = read_u16(bytes, element_offset) as usize;
                    assert!(element_len >= NLA_HEADER_LEN);
                    assert!(element_offset + element_len <= nested_end);
                    let element_type = read_u16(bytes, element_offset + 2);
                    let reply_type = (element_type & !NLA_TYPE_MASK) | NFTA_LIST_ELEM;
                    bytes[element_offset + 2..element_offset + 4]
                        .copy_from_slice(&reply_type.to_ne_bytes());
                    element_offset += element_len.next_multiple_of(4);
                }
                return;
            }
            attribute_offset += attribute_len.next_multiple_of(4);
        }
        panic!("serialized set-element message has no element list");
    }

    fn set_string(set: &OwnedPtr<sys::nftnl_set, FreeSet>, attribute: u32) -> &CStr {
        // SAFETY: The parsed set is live and the requested string attributes are asserted present
        // by these round-trip fixtures.
        let pointer = unsafe { sys::nftnl_set_get_str(set.pointer().as_ptr(), attribute as u16) };
        assert!(!pointer.is_null());
        // SAFETY: libnftnl owns a NUL-terminated string for the lifetime of `set`.
        unsafe { CStr::from_ptr(pointer) }
    }

    fn set_u32(set: &OwnedPtr<sys::nftnl_set, FreeSet>, attribute: u32) -> u32 {
        // SAFETY: The parsed set is live and the fixture includes this numeric attribute.
        unsafe { sys::nftnl_set_get_u32(set.pointer().as_ptr(), attribute as u16) }
    }

    fn set_elements(set: &OwnedPtr<sys::nftnl_set, FreeSet>) -> Vec<(Vec<u8>, u32)> {
        // SAFETY: The set remains live for the iterator's lifetime.
        let iterator = unsafe { sys::nftnl_set_elems_iter_create(set.pointer().as_ptr()) };
        // SAFETY: A non-null result is uniquely owned and paired with the iterator destroy call.
        let iterator =
            unsafe { OwnedPtr::from_alloc(iterator, FreeSetIterator, "test set-element iterator") }
                .unwrap();
        let mut elements = Vec::new();
        loop {
            // SAFETY: The iterator and its underlying set are live. libnftnl returns the current
            // element and advances the iterator.
            let element = unsafe { sys::nftnl_set_elems_iter_next(iterator.pointer().as_ptr()) };
            let Some(element_pointer) = NonNull::new(element) else {
                break;
            };
            let mut key_len = 0u32;
            // SAFETY: The iterator yielded a live element; libnftnl returns its borrowed key.
            let key = unsafe {
                sys::nftnl_set_elem_get(
                    element_pointer.as_ptr(),
                    sys::NFTNL_SET_ELEM_KEY as u16,
                    &mut key_len,
                )
            };
            assert!(!key.is_null());
            // SAFETY: The key pointer is valid for exactly `key_len` bytes while the set is live.
            let key = unsafe { std::slice::from_raw_parts(key.cast::<u8>(), key_len as usize) };
            // SAFETY: The element is live for the duration of this call.
            let has_flags = unsafe {
                sys::nftnl_set_elem_is_set(
                    element_pointer.as_ptr(),
                    sys::NFTNL_SET_ELEM_FLAGS as u16,
                )
            };
            let flags = if has_flags {
                // SAFETY: The element is live and the flags attribute was confirmed present.
                unsafe {
                    sys::nftnl_set_elem_get_u32(
                        element_pointer.as_ptr(),
                        sys::NFTNL_SET_ELEM_FLAGS as u16,
                    )
                }
            } else {
                0
            };
            elements.push((key.to_vec(), flags));
        }
        elements
    }

    fn assert_interval_round_trip<K: SetKey>(
        name: &CStr,
        key_len: u32,
        first: &K,
        after_last: &K,
        address_space_end: &K,
    ) {
        let table = Table::new(c"roundtrip", ProtoFamily::Inet);
        let mut source = IntervalSet::new(name, 41, &table);
        source.add_range(first, Some(after_last)).unwrap();
        source.add_range(address_space_end, None).unwrap();

        let definition = serialize(source.as_set(), MsgType::Add, 51);
        assert_eq!(
            header(definition.as_bytes()).nlmsg_type,
            nft_message_type(libc::NFT_MSG_NEWSET as u16)
        );
        let parsed = allocate_test_set();
        parse_set_definition(&parsed, &definition);
        let parsed_elements = allocate_test_set();
        for elements in source.as_set().elems_iter() {
            let mut elements = serialize(&elements, MsgType::Add, 52);
            assert_eq!(
                header(elements.as_bytes()).nlmsg_type,
                nft_message_type(libc::NFT_MSG_NEWSETELEM as u16)
            );
            // libnftnl emits positional nested types in outbound multi-element requests, while
            // its parser requires the repeated `NFTA_LIST_ELEM` type used in kernel replies.
            // Normalize only that framing detail before exercising the real response parser.
            normalize_element_types_for_kernel_reply(&mut elements);
            parse_set_elements(&parsed_elements, &elements);
        }

        assert_eq!(set_string(&parsed, sys::NFTNL_SET_TABLE), c"roundtrip");
        assert_eq!(set_string(&parsed, sys::NFTNL_SET_NAME), name);
        assert_eq!(set_u32(&parsed, sys::NFTNL_SET_ID), 41);
        assert_eq!(
            set_u32(&parsed, sys::NFTNL_SET_FAMILY),
            ProtoFamily::Inet as u32
        );
        assert_eq!(set_u32(&parsed, sys::NFTNL_SET_KEY_LEN), key_len);
        assert_eq!(
            set_u32(&parsed, sys::NFTNL_SET_FLAGS),
            libc::NFT_SET_INTERVAL as u32
        );
        assert_eq!(
            set_elements(&parsed_elements),
            vec![
                (first.data().into_vec(), 0),
                (
                    after_last.data().into_vec(),
                    libc::NFT_SET_ELEM_INTERVAL_END as u32
                ),
                (address_space_end.data().into_vec(), 0),
            ]
        );
    }

    fn build_flowtable_message(devices: Option<&[&CStr]>) -> NetlinkRequest {
        // SAFETY: Allocation has no preconditions.
        let source = unsafe { sys::nftnl_flowtable_alloc() };
        // SAFETY: A non-null result is uniquely owned and paired with `nftnl_flowtable_free`.
        let source =
            unsafe { OwnedPtr::from_alloc(source, FreeFlowtable, "test flowtable") }.unwrap();
        // SAFETY: The flowtable and static C string are live; libnftnl copies the attribute.
        let result = unsafe {
            sys::nftnl_flowtable_set_str(
                source.pointer().as_ptr(),
                sys::NFTNL_FLOWTABLE_TABLE as u16,
                c"filter".as_ptr(),
            )
        };
        assert_eq!(result, 0);
        // SAFETY: Same invariant as the table name above.
        let result = unsafe {
            sys::nftnl_flowtable_set_str(
                source.pointer().as_ptr(),
                sys::NFTNL_FLOWTABLE_NAME as u16,
                c"fastpath".as_ptr(),
            )
        };
        assert_eq!(result, 0);
        if let Some(devices) = devices {
            let mut pointers: Vec<*const c_char> =
                devices.iter().map(|device| device.as_ptr()).collect();
            pointers.push(ptr::null());
            // SAFETY: The pointer array is null terminated and all strings remain live for the
            // call; libnftnl copies the array into the flowtable.
            let result = unsafe {
                sys::nftnl_flowtable_set_array(
                    source.pointer().as_ptr(),
                    sys::NFTNL_FLOWTABLE_DEVICES as u16,
                    pointers.as_mut_ptr(),
                )
            };
            assert_eq!(result, 0);
        }

        let mut buffer = AlignedNetlinkBuffer::new(nftnl::nft_nlmsg_maxsize() as usize);
        // SAFETY: The buffer is aligned and large enough for the generated flowtable message.
        let message = unsafe {
            sys::nftnl_nlmsg_build_hdr(
                buffer.as_bytes_mut().as_mut_ptr().cast::<c_char>(),
                NFT_MSG_NEWFLOWTABLE,
                ProtoFamily::Inet as u16,
                0,
                61,
            )
        };
        assert!(!message.is_null());
        // SAFETY: Both the header and source flowtable are live and valid for this call.
        unsafe { sys::nftnl_flowtable_nlmsg_build_payload(message, source.pointer().as_ptr()) };
        // SAFETY: `message` points to the start of the still-live aligned buffer.
        let len = unsafe { (*message).nlmsg_len as usize };
        assert!(len <= buffer.capacity());
        NetlinkRequest { buffer, len }
    }

    #[test]
    fn owned_pointer_rejects_null_allocations() {
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: Null carries no ownership obligation.
        let result = unsafe {
            OwnedPtr::<u8, _>::from_alloc(
                ptr::null_mut(),
                CountingDeallocator(drops.clone()),
                "test object",
            )
        };
        let error = match result {
            Ok(_) => panic!("null allocation unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(error.to_string().contains("test object"));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn owned_pointer_deallocates_exactly_once_on_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let allocation = Box::into_raw(Box::new(7u8));
        // SAFETY: The Box allocation is uniquely owned and matches the test deallocator.
        let guard = unsafe {
            OwnedPtr::from_alloc(
                allocation,
                CountingDeallocator(drops.clone()),
                "test object",
            )
        }
        .unwrap();
        drop(guard);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn owned_pointer_transfer_disarms_deallocation() {
        let drops = Arc::new(AtomicUsize::new(0));
        let allocation = Box::into_raw(Box::new(9u8));
        // SAFETY: The Box allocation is uniquely owned and matches the test deallocator.
        let guard = unsafe {
            OwnedPtr::from_alloc(
                allocation,
                CountingDeallocator(drops.clone()),
                "test object",
            )
        }
        .unwrap();
        let transferred = guard.into_non_null();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // SAFETY: Ownership was transferred out of the guard and is reclaimed exactly once here.
        drop(unsafe { Box::from_raw(transferred.as_ptr()) });
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn owned_pointer_deallocates_during_error_unwinding() {
        fn fail(drops: Arc<AtomicUsize>) -> io::Result<()> {
            let allocation = Box::into_raw(Box::new(11u8));
            // SAFETY: The Box allocation is uniquely owned and matches the test deallocator.
            let _guard = unsafe {
                OwnedPtr::from_alloc(allocation, CountingDeallocator(drops), "test object")
            }?;
            Err(io::Error::other("injected failure"))
        }

        let drops = Arc::new(AtomicUsize::new(0));
        assert!(fail(drops.clone()).is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn aligned_buffer_rounds_capacity_and_is_aligned() {
        let buffer = AlignedNetlinkBuffer::new(17);
        assert!(buffer.capacity() >= 17);
        assert_eq!(buffer.capacity() % size_of::<u64>(), 0);
        assert_eq!(
            buffer.as_bytes().as_ptr() as usize % align_of::<libc::nlmsghdr>(),
            0
        );
    }

    #[test]
    fn aligned_buffer_rejects_an_oversized_prefix() {
        let buffer = AlignedNetlinkBuffer::new(32);
        assert!(buffer.prefix(buffer.capacity() + 1).is_err());
    }

    #[test]
    fn top_level_attribute_removal_preserves_message_framing() {
        let attributes: &[(u16, &[u8])] = &[(11, b"a"), (12, b"bc"), (13, b"def")];
        for target in [11, 12, 13] {
            let mut message = synthetic_message(attributes);
            let original_len = message.len;
            // SAFETY: `synthetic_message` created a complete, aligned, bounded netlink message.
            unsafe {
                remove_top_level_attribute(
                    message.buffer.as_bytes_mut().as_mut_ptr().cast::<c_void>(),
                    target,
                )
            };
            message.len = header(message.buffer.as_bytes()).nlmsg_len as usize;
            assert!(message.len < original_len);
            assert_eq!(
                top_level_attributes(message.as_bytes()),
                attributes
                    .iter()
                    .filter(|(attribute_type, _)| *attribute_type != target)
                    .map(|(attribute_type, payload)| (*attribute_type, payload.to_vec()))
                    .collect::<Vec<_>>()
            );
        }

        let mut absent = synthetic_message(attributes);
        let before = absent.as_bytes().to_vec();
        // SAFETY: `synthetic_message` created a complete, aligned, bounded netlink message.
        unsafe {
            remove_top_level_attribute(
                absent.buffer.as_bytes_mut().as_mut_ptr().cast::<c_void>(),
                99,
            )
        };
        assert_eq!(absent.as_bytes(), before);
    }

    #[test]
    fn top_level_attribute_removal_rejects_malformed_lengths() {
        const ATTRIBUTE_OFFSET: usize = size_of::<libc::nlmsghdr>() + 4;

        let mut undersized = synthetic_message(&[(11, b"a")]);
        undersized.buffer.as_bytes_mut()[ATTRIBUTE_OFFSET..ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&3u16.to_ne_bytes());
        let before = undersized.as_bytes().to_vec();
        // SAFETY: The backing allocation is still aligned and bounded despite the malformed NLA.
        unsafe {
            remove_top_level_attribute(
                undersized
                    .buffer
                    .as_bytes_mut()
                    .as_mut_ptr()
                    .cast::<c_void>(),
                11,
            )
        };
        assert_eq!(undersized.as_bytes(), before);

        let mut truncated = synthetic_message(&[(11, b"a")]);
        set_message_len(&mut truncated, ATTRIBUTE_OFFSET + 5);
        let before = truncated.as_bytes().to_vec();
        // SAFETY: The claimed message length stays within the allocation; only NLA padding is
        // deliberately missing.
        unsafe {
            remove_top_level_attribute(
                truncated
                    .buffer
                    .as_bytes_mut()
                    .as_mut_ptr()
                    .cast::<c_void>(),
                11,
            )
        };
        assert_eq!(truncated.as_bytes(), before);

        let mut oversized = synthetic_message(&[(11, b"a")]);
        oversized.buffer.as_bytes_mut()[ATTRIBUTE_OFFSET..ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&32u16.to_ne_bytes());
        let before = oversized.as_bytes().to_vec();
        // SAFETY: The malformed attribute length exceeds the message, not the backing allocation.
        unsafe {
            remove_top_level_attribute(
                oversized
                    .buffer
                    .as_bytes_mut()
                    .as_mut_ptr()
                    .cast::<c_void>(),
                11,
            )
        };
        assert_eq!(oversized.as_bytes(), before);
    }

    #[test]
    fn table_and_set_dump_requests_have_expected_headers() {
        for (request, message_type, seq) in [
            (
                NetlinkRequest::table_dump(17).unwrap(),
                NFT_MSG_GETTABLE,
                17,
            ),
            (NetlinkRequest::set_dump(23).unwrap(), NFT_MSG_GETSET, 23),
        ] {
            let header = header(request.as_bytes());
            assert_eq!(header.nlmsg_type, nft_message_type(message_type));
            assert_eq!(header.nlmsg_seq, seq);
            assert_ne!(header.nlmsg_flags & libc::NLM_F_REQUEST as u16, 0);
            assert_ne!(header.nlmsg_flags & libc::NLM_F_DUMP as u16, 0);
            assert_eq!(
                request.as_bytes()[size_of::<libc::nlmsghdr>()],
                ProtoFamily::Unspec as u8
            );
        }
    }

    #[test]
    fn flowtable_request_is_bounded_and_contains_a_header() {
        let request = NetlinkRequest::flowtable_dump(7).unwrap();
        assert!(request.as_bytes().len() >= size_of::<libc::nlmsghdr>());
        assert!(request.as_bytes().len() <= request.buffer.capacity());
        let header = header(request.as_bytes());
        assert_eq!(header.nlmsg_type, nft_message_type(NFT_MSG_GETFLOWTABLE));
        assert_eq!(header.nlmsg_seq, 7);
        assert_ne!(header.nlmsg_flags & libc::NLM_F_REQUEST as u16, 0);
        assert_ne!(header.nlmsg_flags & libc::NLM_F_DUMP as u16, 0);
        assert_eq!(
            request.as_bytes()[size_of::<libc::nlmsghdr>()],
            ProtoFamily::Unspec as u8
        );
    }

    #[test]
    fn table_and_set_info_round_trip_through_libnftnl() {
        let table = Table::new(c"metadata", ProtoFamily::Inet);
        let table_message = serialize(&table, MsgType::Add, 31);
        let parsed_table = TableInfo::parse(header(table_message.as_bytes())).unwrap();
        assert_eq!(parsed_table.name().unwrap(), "metadata");

        let set = IntervalSet::<Ipv4Addr>::new(c"addresses", 37, &table);
        let set_message = serialize(set.as_set(), MsgType::Add, 32);
        let parsed_set = SetInfo::parse(header(set_message.as_bytes())).unwrap();
        assert_eq!(parsed_set.table().unwrap(), "metadata");
        assert_eq!(parsed_set.name().unwrap(), "addresses");
        assert_eq!(SetInfo::count(header(set_message.as_bytes())), None);
    }

    #[test]
    fn set_count_parses_valid_and_missing_attributes() {
        let count = synthetic_message(&[
            (7, b"ignored"),
            (19, b"rbtree\0"),
            (20, &4_228_762u32.to_be_bytes()),
        ]);
        assert_eq!(SetInfo::count(header(count.as_bytes())), Some(4_228_762));

        let missing = synthetic_message(&[(7, b"ignored"), (19, b"rbtree\0")]);
        assert_eq!(SetInfo::count(header(missing.as_bytes())), None);

        let short_count = synthetic_message(&[(20, &[0, 1, 2])]);
        assert_eq!(SetInfo::count(header(short_count.as_bytes())), None);
    }

    #[test]
    fn set_count_rejects_malformed_messages() {
        const ATTRIBUTE_OFFSET: usize = size_of::<libc::nlmsghdr>() + 4;

        let mut too_short = synthetic_message(&[]);
        set_message_len(&mut too_short, size_of::<libc::nlmsghdr>());
        assert_eq!(SetInfo::count(header(too_short.as_bytes())), None);

        let mut undersized = synthetic_message(&[(20, &1u32.to_be_bytes())]);
        undersized.buffer.as_bytes_mut()[ATTRIBUTE_OFFSET..ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&3u16.to_ne_bytes());
        assert_eq!(SetInfo::count(header(undersized.as_bytes())), None);

        let mut truncated = synthetic_message(&[(20, &1u32.to_be_bytes())]);
        truncated.buffer.as_bytes_mut()[ATTRIBUTE_OFFSET..ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&12u16.to_ne_bytes());
        assert_eq!(SetInfo::count(header(truncated.as_bytes())), None);
    }

    #[test]
    fn ipv4_interval_set_round_trips_through_libnftnl() {
        assert_interval_round_trip(
            c"addresses_v4",
            4,
            &"10.0.0.0".parse::<Ipv4Addr>().unwrap(),
            &"10.0.1.0".parse::<Ipv4Addr>().unwrap(),
            &"255.255.255.0".parse::<Ipv4Addr>().unwrap(),
        );
    }

    #[test]
    fn ipv6_interval_set_round_trips_through_libnftnl() {
        assert_interval_round_trip(
            c"addresses_v6",
            16,
            &"2001:db8::".parse::<Ipv6Addr>().unwrap(),
            &"2001:db8::2".parse::<Ipv6Addr>().unwrap(),
            &"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"
                .parse::<Ipv6Addr>()
                .unwrap(),
        );
    }

    #[test]
    fn existing_set_element_messages_omit_transaction_local_id() {
        let table = Table::new(c"roundtrip", ProtoFamily::Inet);
        let mut source = IntervalSet::<Ipv4Addr>::existing(c"addresses", &table);
        source
            .add_range(
                &"10.0.0.0".parse().unwrap(),
                Some(&"10.0.0.1".parse().unwrap()),
            )
            .unwrap();
        let mut iterator = source.as_set().elems_iter();
        let element_message = iterator.next().unwrap();
        let message = serialize(&ExistingElements::new(element_message), MsgType::Add, 70);
        const NFGENMSG_LEN: usize = 4;
        const NLA_HEADER_LEN: usize = 4;
        let bytes = message.as_bytes();
        let mut offset = size_of::<libc::nlmsghdr>() + NFGENMSG_LEN;
        let mut types = Vec::new();
        while offset + NLA_HEADER_LEN <= bytes.len() {
            let len = u16::from_ne_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            types.push(
                u16::from_ne_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) & 0x3fff,
            );
            offset += len.next_multiple_of(4);
        }
        assert!(!types.contains(&4), "set-list ID was retained: {types:?}");
        assert!(types.contains(&2), "set name is missing: {types:?}");
    }

    #[test]
    fn every_existing_set_element_message_omits_transaction_local_id() {
        let table = Table::new(c"roundtrip", ProtoFamily::Inet);
        let mut source = IntervalSet::<Ipv4Addr>::existing(c"addresses", &table);
        for value in 0..5_000u32 {
            source
                .add_range(
                    &Ipv4Addr::from(value * 2),
                    Some(&Ipv4Addr::from(value * 2 + 1)),
                )
                .unwrap();
        }

        let mut message_count = 0;
        for elements in source.as_set().elems_iter() {
            let message = serialize(&ExistingElements::new(elements), MsgType::Add, 71);
            let types: Vec<_> = top_level_attributes(message.as_bytes())
                .into_iter()
                .map(|(attribute_type, _)| attribute_type)
                .collect();
            assert!(!types.contains(&4), "set-list ID was retained: {types:?}");
            assert!(types.contains(&2), "set name is missing: {types:?}");
            message_count += 1;
        }
        assert!(message_count > 1);
    }

    #[test]
    fn existing_set_message_omits_id_and_preserves_selector() {
        let table = Table::new(c"roundtrip", ProtoFamily::Inet);
        let source = IntervalSet::<Ipv4Addr>::existing(c"addresses", &table);
        let raw = serialize(source.as_set(), MsgType::Del, 72);
        assert!(
            top_level_attributes(raw.as_bytes())
                .iter()
                .any(|(attribute_type, _)| *attribute_type == 10),
            "fixture did not contain a transaction-local set ID"
        );

        let message = serialize(&ExistingSetMessage::new(source.as_set()), MsgType::Del, 73);
        let message_header = header(message.as_bytes());
        assert_eq!(
            message_header.nlmsg_type,
            nft_message_type(libc::NFT_MSG_DELSET as u16)
        );
        assert_eq!(message_header.nlmsg_seq, 73);
        assert_ne!(message_header.nlmsg_flags & libc::NLM_F_ACK as u16, 0);
        let types: Vec<_> = top_level_attributes(message.as_bytes())
            .into_iter()
            .map(|(attribute_type, _)| attribute_type)
            .collect();
        assert!(!types.contains(&10), "set ID was retained: {types:?}");
        assert!(types.contains(&1), "table name is missing: {types:?}");
        assert!(types.contains(&2), "set name is missing: {types:?}");

        let parsed = allocate_test_set();
        parse_set_definition(&parsed, &message);
        assert_eq!(set_string(&parsed, sys::NFTNL_SET_TABLE), c"roundtrip");
        assert_eq!(set_string(&parsed, sys::NFTNL_SET_NAME), c"addresses");
        // SAFETY: The parsed set remains live for this attribute-presence query.
        assert!(!unsafe {
            sys::nftnl_set_is_set(parsed.pointer().as_ptr(), sys::NFTNL_SET_ID as u16)
        });
    }

    #[test]
    fn named_lookup_round_trips_without_a_set_id() {
        let table = Table::new(c"roundtrip", ProtoFamily::Inet);
        let chain = Chain::new(c"input", &table);
        let mut source = Rule::new(&chain);
        source.add_expr(&NamedLookup::new(c"addresses"));
        let message = serialize(&source, MsgType::Add, 74);
        let parsed = allocate_test_rule();
        parse_rule(&parsed, &message);

        // SAFETY: The parsed rule remains live for the iterator's lifetime.
        let iterator = unsafe { sys::nftnl_expr_iter_create(parsed.pointer().as_ptr()) };
        // SAFETY: A non-null result is uniquely owned and paired with the iterator destroy call.
        let iterator = unsafe {
            OwnedPtr::from_alloc(iterator, FreeExpressionIterator, "test expression iterator")
        }
        .unwrap();
        // SAFETY: The iterator and its underlying parsed rule are live.
        let expression = unsafe { sys::nftnl_expr_iter_next(iterator.pointer().as_ptr()) };
        let expression = NonNull::new(expression).expect("lookup expression is missing");
        // SAFETY: The expression is live for these attribute-presence queries.
        let has_source_register = unsafe {
            sys::nftnl_expr_is_set(expression.as_ptr(), sys::NFTNL_EXPR_LOOKUP_SREG as u16)
        };
        assert!(has_source_register);
        // SAFETY: The expression is live and the source-register attribute is present.
        let source_register = unsafe {
            sys::nftnl_expr_get_u32(expression.as_ptr(), sys::NFTNL_EXPR_LOOKUP_SREG as u16)
        };
        assert_eq!(source_register, libc::NFT_REG_1 as u32);
        // SAFETY: The expression is live for this attribute-presence query.
        let has_set_name = unsafe {
            sys::nftnl_expr_is_set(expression.as_ptr(), sys::NFTNL_EXPR_LOOKUP_SET as u16)
        };
        assert!(has_set_name);
        // SAFETY: The expression is live and the set-name attribute is present.
        let set_name = unsafe {
            sys::nftnl_expr_get_str(expression.as_ptr(), sys::NFTNL_EXPR_LOOKUP_SET as u16)
        };
        assert!(!set_name.is_null());
        // SAFETY: libnftnl returned a NUL-terminated string owned by the live expression.
        assert_eq!(unsafe { CStr::from_ptr(set_name) }, c"addresses");
        // SAFETY: The expression is live for this attribute-presence query.
        let has_set_id = unsafe {
            sys::nftnl_expr_is_set(expression.as_ptr(), sys::NFTNL_EXPR_LOOKUP_SET_ID as u16)
        };
        assert!(!has_set_id);
        // SAFETY: The iterator and its underlying parsed rule remain live.
        let next = unsafe { sys::nftnl_expr_iter_next(iterator.pointer().as_ptr()) };
        assert!(next.is_null());
    }

    #[test]
    fn rule_flush_serializes_a_handle_free_chain_selector() {
        let table = Table::new(c"roundtrip", ProtoFamily::Inet);
        let chain = Chain::new(c"input", &table);
        let message = serialize(&RuleFlush::new(&chain), MsgType::Del, 75);
        let message_header = header(message.as_bytes());
        assert_eq!(
            message_header.nlmsg_type,
            nft_message_type(libc::NFT_MSG_DELRULE as u16)
        );
        assert_eq!(message_header.nlmsg_seq, 75);
        assert_eq!(
            message_header.nlmsg_flags,
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16,
            "flush should request only the deletion and its acknowledgement"
        );

        let parsed = allocate_test_rule();
        parse_rule(&parsed, &message);
        assert_eq!(rule_string(&parsed, sys::NFTNL_RULE_TABLE), c"roundtrip");
        assert_eq!(rule_string(&parsed, sys::NFTNL_RULE_CHAIN), c"input");
        // SAFETY: The parsed rule remains live and contains the family attribute.
        let family = unsafe {
            sys::nftnl_rule_get_u32(parsed.pointer().as_ptr(), sys::NFTNL_RULE_FAMILY as u16)
        };
        assert_eq!(family, ProtoFamily::Inet as u32);
        // SAFETY: The parsed rule remains live for this attribute-presence query.
        let has_handle = unsafe {
            sys::nftnl_rule_is_set(parsed.pointer().as_ptr(), sys::NFTNL_RULE_HANDLE as u16)
        };
        assert!(!has_handle);
    }

    #[test]
    fn flowtable_devices_round_trip_through_libnftnl() {
        let message = build_flowtable_message(Some(&[c"wan0"]));
        let parsed = Flowtable::parse(header(message.as_bytes())).unwrap();
        assert_eq!(parsed.device_names().unwrap(), vec!["wan0"]);

        let message = build_flowtable_message(Some(&[c"wan0", c"lan0", c"guest0"]));
        let parsed = Flowtable::parse(header(message.as_bytes())).unwrap();
        assert_eq!(
            parsed.device_names().unwrap(),
            vec!["wan0", "lan0", "guest0"]
        );
    }

    #[test]
    fn flowtable_without_devices_fails_closed() {
        let message = build_flowtable_message(None);
        let parsed = Flowtable::parse(header(message.as_bytes())).unwrap();
        let error = parsed.device_names().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("no device array"));
    }

    #[test]
    fn flowtable_with_invalid_utf8_device_fails_closed() {
        let invalid = c"wan\xff";
        let message = build_flowtable_message(Some(&[invalid]));
        let parsed = Flowtable::parse(header(message.as_bytes())).unwrap();
        let error = parsed.device_names().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not UTF-8"));
    }
}
