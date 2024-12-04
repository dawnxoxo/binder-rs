#![allow(non_camel_case_types)]
#![allow(unused)]

use bitflags::bitflags;
use nix::{
    ioctl_none, ioctl_read, ioctl_readwrite, ioctl_write_int, ioctl_write_ptr,
    libc::{pid_t, uid_t},
};
use num_traits::ToBytes;
use std::{ffi::c_void, mem::size_of, os::fd::RawFd};

macro_rules! B_PACK_CHARS {
    ($c1:expr, $c2:expr, $c3:expr, $c4:expr) => {
        (($c1 as u32) << 24) | (($c2 as u32) << 16) | (($c3 as u32) << 8) | ($c4 as u32)
    };
}

const _IOC_NRBITS: u8 = 8;
const _IOC_TYPEBITS: u8 = 8;

/*
 * Let any architecture override either of the following before
 * including this file.
 */

const _IOC_SIZEBITS: u8 = 14;
const _IOC_DIRBITS: u8 = 2;
const _IOC_NRSHIFT: u8 = 0;

const _IOC_TYPESHIFT: u8 = (_IOC_NRSHIFT + _IOC_NRBITS);
const _IOC_SIZESHIFT: u8 = (_IOC_TYPESHIFT + _IOC_TYPEBITS);
const _IOC_DIRSHIFT: u8 = (_IOC_SIZESHIFT + _IOC_SIZEBITS);

/*
 * Direction bits, which any architecture can choose to override
 * before including this file.
 *
 * NOTE: _IOC_WRITE means userland is writing and kernel is
 * reading. _IOC_READ means userland is reading and kernel is writing.
 */
const _IOC_NONE: u8 = 0;
const _IOC_WRITE: u8 = 1;
const _IOC_READ: u8 = 2;

macro_rules! _IOC {
    ($dir:expr, $type:expr, $nr:expr, $size:expr) => {
        (($dir as u32) << _IOC_DIRSHIFT)
            | (($type as u32) << _IOC_TYPESHIFT)
            | (($nr as u32) << _IOC_NRSHIFT)
            | (($size as u32) << _IOC_SIZESHIFT)
    };
}

/*
 * Used to create numbers.
 *
 * NOTE: _IOW means userland is writing and kernel is reading. _IOR
 * means userland is reading and kernel is writing.
 */

macro_rules! _IO {
    ($type:expr, $nr:expr) => {
        _IOC!(_IOC_NONE, ($type), ($nr), 0)
    };
}

macro_rules! _IOR {
    ($type:expr, $nr:expr, $argtype:ident) => {
        _IOC!(_IOC_READ, ($type), ($nr), size_of::<$argtype>())
    };
}

macro_rules! _IOW {
    ($type:expr, $nr:expr, $argtype:ident) => {
        _IOC!(_IOC_WRITE, ($type), ($nr), size_of::<$argtype>())
    };
}

macro_rules! _IOWR {
    ($type:expr, $nr:expr, $argtype:ident) => {
        _IOC!(
            _IOC_READ | _IOC_WRITE,
            ($type),
            ($nr),
            size_of::<$argtype>()
        )
    };
}

const B_TYPE_LARGE: u8 = 0x85;

#[repr(u32)]
enum BinderType {
    BinderTypeBinder = B_PACK_CHARS!('s', 'b', '*', B_TYPE_LARGE),
    BinderTypeWeakBinder = B_PACK_CHARS!('w', 'b', '*', B_TYPE_LARGE),
    BinderTypeHandle = B_PACK_CHARS!('s', 'h', '*', B_TYPE_LARGE),
    BinderTypeWeakHandle = B_PACK_CHARS!('w', 'h', '*', B_TYPE_LARGE),
    BinderTypeFd = B_PACK_CHARS!('f', 'd', '*', B_TYPE_LARGE),
    BinderTypeFda = B_PACK_CHARS!('f', 'd', 'a', B_TYPE_LARGE),
    BinderTypePtr = B_PACK_CHARS!('p', 't', '*', B_TYPE_LARGE),
}

enum FlatBinderFlag {
    FlatBinderFlagPriorityMask = 0xff,
    FlatBinderFlagAcceptsFds = 0x100,

    /**
     * @FLAT_BINDER_FLAG_TXN_SECURITY_CTX: request security contexts
     *
     * Only when set, causes senders to include their security
     * context
     */
    FlatBinderFlagTxnSecurityCtx = 0x1000,
}

pub type binder_size_t = u64;
pub type binder_uintptr_t = u64;

/**
 * struct binder_object_header - header shared by all binder metadata objects.
 * @type:	type of the object
 */
#[repr(C)]
struct binder_object_header {
    _type: u32,
}

#[repr(C)]
union binder_object_union {
    binder: binder_uintptr_t, /* local object */
    handle: u32,              /* remote object */
}

/*
 * This is the flattened representation of a Binder object for transfer
 * between processes.  The 'offsets' supplied as part of a binder transaction
 * contains offsets into the data where these structures occur.  The Binder
 * driver takes care of re-writing the structure type and data as it moves
 * between processes.
 */
#[repr(C)]
struct flat_binder_object {
    hdr: binder_object_header,
    flags: u32,

    /* 8 bytes of data. */
    binder: binder_object_union,

    /* extra data associated with local object */
    cookie: binder_uintptr_t,
}

/**
 * struct binder_fd_object - describes a filedescriptor to be fixed up.
 * @hdr:	common header structure
 * @pad_flags:	padding to remain compatible with old userspace code
 * @pad_binder:	padding to remain compatible with old userspace code
 * @fd:		file descriptor
 * @cookie:	opaque data, used by user-space
 */
#[repr(C)]
union binder_fd_union {
    pad_binder: binder_uintptr_t,
    fd: u32,
}

#[repr(C)]
struct binder_fd_object {
    hdr: binder_object_header,
    pad_flags: u32,

    binder: binder_fd_union,

    cookie: binder_uintptr_t,
}

/* struct binder_buffer_object - object describing a userspace buffer
 * @hdr:		common header structure
 * @flags:		one or more BINDER_BUFFER_* flags
 * @buffer:		address of the buffer
 * @length:		length of the buffer
 * @parent:		index in offset array pointing to parent buffer
 * @parent_offset:	offset in @parent pointing to this buffer
 *
 * A binder_buffer object represents an object that the
 * binder kernel driver can copy verbatim to the target
 * address space. A buffer itself may be pointed to from
 * within another buffer, meaning that the pointer inside
 * that other buffer needs to be fixed up as well. This
 * can be done by setting the BINDER_BUFFER_FLAG_HAS_PARENT
 * flag in @flags, by setting @parent buffer to the index
 * in the offset array pointing to the parent binder_buffer_object,
 * and by setting @parent_offset to the offset in the parent buffer
 * at which the pointer to this buffer is located.
 */
#[repr(C)]
struct binder_buffer_object {
    hdr: binder_object_header,
    flags: u32,
    buffer: binder_uintptr_t,
    length: binder_size_t,
    parent: binder_size_t,
    parent_offset: binder_size_t,
}

#[repr(C)]
enum binder_buffer_flags {
    BINDER_BUFFER_FLAG_HAS_PARENT = 0x01,
}

/* struct binder_fd_array_object - object describing an array of fds in a buffer
 * @hdr:		common header structure
 * @pad:		padding to ensure correct alignment
 * @num_fds:		number of file descriptors in the buffer
 * @parent:		index in offset array to buffer holding the fd array
 * @parent_offset:	start offset of fd array in the buffer
 *
 * A binder_fd_array object represents an array of file
 * descriptors embedded in a binder_buffer_object. It is
 * different from a regular binder_buffer_object because it
 * describes a list of file descriptors to fix up, not an opaque
 * blob of memory, and hence the kernel needs to treat it differently.
 *
 * An example of how this would be used is with Android's
 * native_handle_t object, which is a struct with a list of integers
 * and a list of file descriptors. The native_handle_t struct itself
 * will be represented by a struct binder_buffer_objct, whereas the
 * embedded list of file descriptors is represented by a
 * struct binder_fd_array_object with that binder_buffer_object as
 * a parent.
 */
#[repr(C)]
struct binder_fd_array_object {
    hdr: binder_object_header,
    pad: u32,
    num_fds: binder_size_t,
    parent: binder_size_t,
    parent_offset: binder_size_t,
}

/*
 * On 64-bit platforms where user code may run in 32-bits the driver must
 * translate the buffer (and local binder) addresses appropriately.
 */
#[repr(C)]
pub struct BinderWriteRead {
    pub write_size: binder_size_t,     /* bytes to write */
    pub write_consumed: binder_size_t, /* bytes consumed by driver */
    pub write_buffer: *mut u8,
    pub read_size: binder_size_t,     /* bytes to read */
    pub read_consumed: binder_size_t, /* bytes consumed by driver */
    pub read_buffer: *mut u8,
}

/* Use with BINDER_VERSION, driver fills in fields. */
pub type binder_protocol_version = u32;

/* This is the current protocol version. */
const BINDER_CURRENT_PROTOCOL_VERSION: u32 = 8;

/*
 * Use with BINDER_GET_NODE_DEBUG_INFO, driver reads ptr, writes to all fields.
 * Set ptr to NULL for the first call to get the info for the first node, and
 * then repeat the call passing the previously returned value to get the next
 * nodes.  ptr will be 0 when there are no more nodes.
 */
#[derive(Default)]
#[repr(C)]
pub struct binder_node_debug_info {
    pub ptr: binder_uintptr_t,
    cookie: binder_uintptr_t,
    has_strong_ref: u32,
    has_weak_ref: u32,
}

#[repr(C)]
struct binder_node_info_for_ref {
    handle: u32,
    strong_count: u32,
    weak_count: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

#[repr(C)]
struct binder_freeze_info {
    pid: u32,
    enable: u32,
    timeout_ms: u32,
}

#[repr(C)]
struct binder_frozen_status_info {
    pid: u32,

    /* process received sync transactions since last frozen
     * bit 0: received sync transaction after being frozen
     * bit 1: new pending sync transaction during freezing
     */
    sync_recv: u32,

    /* process received async transactions since last frozen */
    async_recv: u32,
}

#[repr(C)]
struct binder_frozen_state_info {
    cookie: binder_uintptr_t,
    is_frozen: u32,
    reserved: u32,
}

/* struct binder_extened_error - extended error information
 * @id:		identifier for the failed operation
 * @command:	command as defined by binder_driver_return_protocol
 * @param:	parameter holding a negative errno value
 *
 * Used with BINDER_GET_EXTENDED_ERROR. This extends the error information
 * returned by the driver upon a failed operation. Userspace can pull this
 * data to properly handle specific error scenarios.
 */
#[repr(C)]
struct binder_extended_error {
    id: u32,
    command: u32,
    param: i32,
}

#[repr(u32)]
enum BinderOperation {
    BINDER_WRITE_READ = _IOWR!('b', 1, BinderWriteRead),
    BINDER_SET_IDLE_TIMEOUT = _IOW!('b', 3, i64),
    BINDER_SET_MAX_THREADS = _IOW!('b', 5, u32),
    BINDER_SET_IDLE_PRIORITY = _IOW!('b', 6, i32),
    BINDER_SET_CONTEXT_MGR = _IOW!('b', 7, i32),
    BINDER_THREAD_EXIT = _IOW!('b', 8, i32),
    BINDER_VERSION = _IOWR!('b', 9, binder_protocol_version),
    BINDER_GET_NODE_DEBUG_INFO = _IOWR!('b', 11, binder_node_debug_info),
    BINDER_GET_NODE_INFO_FOR_REF = _IOWR!('b', 12, binder_node_info_for_ref),
    BINDER_SET_CONTEXT_MGR_EXT = _IOW!('b', 13, flat_binder_object),
    BINDER_FREEZE = _IOW!('b', 14, binder_freeze_info),
    BINDER_GET_FROZEN_INFO = _IOWR!('b', 15, binder_frozen_status_info),
    BINDER_ENABLE_ONEWAY_SPAM_DETECTION = _IOW!('b', 16, u32),
    BINDER_GET_EXTENDED_ERROR = _IOWR!('b', 17, binder_extended_error),
}

ioctl_readwrite!(binder_write_read, 'b', 1, BinderWriteRead);
ioctl_write_ptr!(binder_set_max_threads, 'b', 5, u32);
ioctl_write_ptr!(binder_thread_exit, 'b', 8, i32);
ioctl_readwrite!(binder_version, 'b', 9, binder_protocol_version);
ioctl_readwrite!(binder_get_node_debug_info, 'b', 11, binder_node_debug_info);

/*
 * NOTE: Two special error codes you should check for when calling
 * in to the driver are:
 *
 * EINTR -- The operation has been interupted.  This should be
 * handled by retrying the ioctl() until a different error code
 * is returned.
 *
 * ECONNREFUSED -- The driver is no longer accepting operations
 * from your process.  That is, the process is being destroyed.
 * You should handle this by exiting from your process.  Note
 * that once this error code is returned, all further calls to
 * the driver from any thread will return this same code.
 */
bitflags! {
    pub struct TransactionFlags : u32 {
        const TF_ONE_WAY = 0x01;     /* this is a one-way call: async, no return */
        const TF_ROOT_OBJECT = 0x04; /* contents are the component's root object */
        const TF_STATUS_CODE = 0x08; /* contents are a 32-bit status code */
        const TF_ACCEPT_FDS = 0x10;  /* allow replies with file descriptors */
        const TF_CLEAR_BUF = 0x20;   /* clear buffer on txn complete */
        const TF_UPDATE_TXN = 0x40;  /* update the outdated pending async txn */
    }
}

#[repr(C)]
pub struct binder_transaction_data {
    /* The first two are only used for bcTRANSACTION and brTRANSACTION,
     * identifying the target and contents of the transaction.
     */
    pub target: binder_uintptr_t,
    pub cookie: binder_uintptr_t, /* target object cookie */
    pub code: u32,                /* transaction command */

    /* General information about the transaction. */
    pub flags: u32,
    pub sender_pid: pid_t,
    pub sender_euid: uid_t,
    pub data_size: binder_size_t,    /* number of bytes of data */
    pub offsets_size: binder_size_t, /* number of bytes of offsets */

    /* transaction data */
    pub data: *mut u8,
    /* offsets from buffer to flat_binder_object structs */
    pub offsets: *mut usize,
}

#[repr(C)]
struct binder_transaction_data_secctx {
    transaction_data: binder_transaction_data,
    secctx: binder_uintptr_t,
}

#[repr(C)]
pub struct binder_transaction_data_sg {
    pub transaction_data: binder_transaction_data,
    pub buffers_size: binder_size_t,
}

#[macro_export]
macro_rules! ALIGN {
    ($x:expr, $a:expr) => {
        ((($x) + ($a - 1)) & !($a - 1))
    };
}

impl binder_transaction_data_sg {
    pub fn get_transaction_size(&self) -> u64 {
        self.transaction_data.data_size
            + self.transaction_data.offsets_size
            + ALIGN!(self.buffers_size, size_of::<binder_uintptr_t>() as u64)
    }
}

#[repr(C)]
struct binder_ptr_cookie {
    ptr: binder_uintptr_t,
    cookie: binder_uintptr_t,
}

#[repr(C, packed)]
struct binder_handle_cookie {
    handle: u32,
    cookie: binder_uintptr_t,
}

#[repr(C)]
struct binder_pri_desc {
    priority: i32,
    desc: u32,
}

#[repr(C)]
struct binder_pri_ptr_cookie {
    priority: i32,
    ptr: binder_uintptr_t,
    cookie: binder_uintptr_t,
}

#[repr(u32)]
pub enum binder_driver_return_protocol {
    BR_ERROR = _IOR!('r', 0, i32),
    BR_OK = _IO!('r', 1),
    BR_TRANSACTION_SEC_CTX = _IOR!('r', 2, binder_transaction_data_secctx),
    BR_TRANSACTION = _IOR!('r', 2, binder_transaction_data),
    BR_REPLY = _IOR!('r', 3, binder_transaction_data),
    BR_ACQUIRE_RESULT = _IOR!('r', 4, i32),
    BR_DEAD_REPLY = _IO!('r', 5),
    BR_TRANSACTION_COMPLETE = _IO!('r', 6),
    BR_INCREFS = _IOR!('r', 7, binder_ptr_cookie),
    BR_ACQUIRE = _IOR!('r', 8, binder_ptr_cookie),
    BR_RELEASE = _IOR!('r', 9, binder_ptr_cookie),
    BR_DECREFS = _IOR!('r', 10, binder_ptr_cookie),
    BR_ATTEMPT_ACQUIRE = _IOR!('r', 11, binder_pri_ptr_cookie),
    BR_NOOP = _IO!('r', 12),
    BR_SPAWN_LOOPER = _IO!('r', 13),
    BR_FINISHED = _IO!('r', 14),
    BR_DEAD_BINDER = _IOR!('r', 15, binder_uintptr_t),
    BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR!('r', 16, binder_uintptr_t),
    BR_FAILED_REPLY = _IO!('r', 17),
    BR_FROZEN_REPLY = _IO!('r', 18),
    BR_ONEWAY_SPAM_SUSPECT = _IO!('r', 19),
    BR_TRANSACTION_PENDING_FROZEN = _IO!('r', 20),
    BR_FROZEN_BINDER = _IOR!('r', 21, binder_frozen_state_info),
    BR_CLEAR_FREEZE_NOTIFICATION_DONE = _IOR!('r', 22, binder_uintptr_t),
}

#[repr(u32)]
pub enum binder_driver_command_protocol {
    BC_TRANSACTION = _IOW!('c', 0, binder_transaction_data),
    BC_REPLY = _IOW!('c', 1, binder_transaction_data),
    BC_ACQUIRE_RESULT = _IOW!('c', 2, i32),
    BC_FREE_BUFFER = _IOW!('c', 3, binder_uintptr_t),
    BC_INCREFS = _IOW!('c', 4, u32),
    BC_ACQUIRE = _IOW!('c', 5, u32),
    BC_RELEASE = _IOW!('c', 6, u32),
    BC_DECREFS = _IOW!('c', 7, u32),
    BC_INCREFS_DONE = _IOW!('c', 8, binder_ptr_cookie),
    BC_ACQUIRE_DONE = _IOW!('c', 9, binder_ptr_cookie),
    BC_ATTEMPT_ACQUIRE = _IOW!('c', 10, binder_pri_desc),
    BC_REGISTER_LOOPER = _IO!('c', 11),
    BC_ENTER_LOOPER = _IO!('c', 12),
    BC_EXIT_LOOPER = _IO!('c', 13),
    BC_REQUEST_DEATH_NOTIFICATION = _IOW!('c', 14, binder_handle_cookie),
    BC_CLEAR_DEATH_NOTIFICATION = _IOW!('c', 15, binder_handle_cookie),
    BC_DEAD_BINDER_DONE = _IOW!('c', 16, binder_uintptr_t),
    BC_TRANSACTION_SG = _IOW!('c', 17, binder_transaction_data_sg),
    BC_REPLY_SG = _IOW!('c', 18, binder_transaction_data_sg),
    BC_REQUEST_FREEZE_NOTIFICATION = _IOW!('c', 19, binder_handle_cookie),
    BC_CLEAR_FREEZE_NOTIFICATION = _IOW!('c', 20, binder_handle_cookie),
    BC_FREEZE_NOTIFICATION_DONE = _IOW!('c', 21, binder_uintptr_t),
}
