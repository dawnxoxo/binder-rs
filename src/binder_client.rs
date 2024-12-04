use crate::binder::binder_driver_command_protocol::*;
use crate::binder::*;
use crate::parcel::*;
use crate::ALIGN;
use core::{error, slice};
use nix::{
    fcntl::{open, OFlag},
    sys::{
        mman::{mmap, munmap, MapFlags, ProtFlags},
        stat::Mode,
    },
};
use num_traits::zero;
use std::u32;
use std::{
    num::NonZero,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    ptr::{null_mut, NonNull},
};
const BINDER_DEVICE: &str = "/dev/hwbinder";
const DEFAULT_VM_SIZE: usize = 4 * 1024 * 1024;
const MAX_TRANSACTION_SIZE: u64 = 1024 * 1024;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

pub struct BinderClient {
    fd: OwnedFd,
    vmstart: *mut c_void,
    vmsize: usize,
    parcel: Parcel,
}

macro_rules! define_binder_cmd {
    ($name:ident, $cmd:expr $(, $arg:ident: $type:ty)*) => {
        pub fn $name(&mut self $(,$arg : $type)*) -> Result<()> {
            self.parcel.write_cmd($cmd)?;
            $(self.parcel.write($arg)?;)*
            self.write()
        }
    };
}

impl BinderClient {
    pub fn new(addr: Option<NonZero<usize>>, size: Option<NonZero<usize>>) -> Result<Self> {
        let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC;
        let fd = unsafe { OwnedFd::from_raw_fd(open(BINDER_DEVICE, flags, Mode::empty())?) };

        let mut flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE;
        if addr.is_some() {
            flags |= MapFlags::MAP_FIXED_NOREPLACE;
        }

        let size = size.unwrap_or(NonZero::new(DEFAULT_VM_SIZE).unwrap());

        let vmstart = unsafe { mmap(addr, size, ProtFlags::PROT_READ, flags, &fd, 0)?.as_ptr() };

        Ok(Self {
            fd,
            vmstart,
            vmsize: size.into(),
            parcel: Parcel::empty(),
        })
    }

    fn write_read(
        &mut self,
        should_write: bool,
        read_buffer: Option<&mut [u8]>,
        read_consumed: Option<&mut u64>,
    ) -> Result<()> {
        let mut read_size = 0;
        let read_buffer = read_buffer
            .map(|a| {
                read_size = a.len();
                a.as_mut_ptr()
            })
            .unwrap_or(null_mut());

        let mut write_size = 0;
        let mut write_buffer = null_mut();
        if should_write {
            write_buffer = self.parcel.as_mut_ptr();
            write_size = self.parcel.len()
        }

        let mut data = BinderWriteRead {
            write_size: write_size as u64,
            write_consumed: 0,
            write_buffer,

            read_size: read_size as u64,
            read_consumed: 0,
            read_buffer,
        };

        unsafe {
            binder_write_read(self.fd.as_raw_fd(), &mut data)?;
        }

        if let Some(read_consumed) = read_consumed {
            *read_consumed = data.read_consumed;
        }

        if should_write {
            self.parcel.reset();
        }

        Ok(())
    }

    fn write(&mut self) -> Result<()> {
        self.write_read(true, None, None)
    }

    pub fn read(&mut self, read_buffer: &mut [u8], read_consumed: &mut u64) -> Result<()> {
        self.write_read(false, Some(read_buffer), Some(read_consumed))
    }

    pub fn check_version(&mut self) -> Result<binder_protocol_version> {
        let mut version = 0;

        unsafe {
            binder_version(self.fd.as_raw_fd(), &mut version)?;
        }

        Ok(version)
    }

    pub fn node_exists(&mut self, ptr: binder_uintptr_t) -> Result<bool> {
        let mut info = binder_node_debug_info::default();

        unsafe {
            binder_get_node_debug_info(self.fd.as_raw_fd(), &mut info)?;
        }

        Ok(info.ptr == ptr)
    }

    pub fn set_max_threads(&mut self, max_threads: u32) -> Result<()> {
        unsafe {
            binder_set_max_threads(self.fd.as_raw_fd(), &max_threads)?;
        }

        Ok(())
    }

    pub fn thread_exit(&mut self) -> Result<()> {
        unsafe {
            binder_thread_exit(self.fd.as_raw_fd(), &zero())?;
        }

        Ok(())
    }

    fn dispatch_transaction(
        &mut self,
        parcel: &mut Parcel,
        is_reply: bool,
        target: u32,
        code: u32,
        flags: TransactionFlags,
        read_buffer: Option<&mut [u8]>,
        read_consumed: Option<&mut u64>,
    ) -> Result<()> {
        self.parcel.write_cmd(match is_reply {
            true => BC_REPLY_SG,
            false => BC_TRANSACTION_SG,
        })?;

        let txn: binder_transaction_data_sg = binder_transaction_data_sg {
            transaction_data: binder_transaction_data {
                target: target as binder_uintptr_t,
                cookie: 0,
                code,
                flags: flags.bits(),
                sender_pid: 0,
                sender_euid: 0,
                data_size: parcel.len() as u64,
                offsets_size: parcel.offsets_len() as u64,
                data: parcel.as_mut_ptr(),
                offsets: parcel.offsets().as_mut_ptr(),
            },
            buffers_size: ALIGN!(parcel.buffers_size(), size_of::<binder_uintptr_t>() as u64),
        };

        if txn.get_transaction_size() > MAX_TRANSACTION_SIZE {
            return Err(crate::Error::TxnTooBig.into());
        }

        self.parcel.write_slice(unsafe {
            slice::from_raw_parts(
                &txn as *const _ as *const u8,
                size_of::<binder_transaction_data_sg>(),
            )
        })?;
        self.write_read(true, read_buffer, read_consumed)
    }

    pub fn transact(
        &mut self,
        parcel: &mut Parcel,
        target: u32,
        code: u32,
        flags: TransactionFlags,
        read_buffer: Option<&mut [u8]>,
        read_consumed: Option<&mut u64>,
    ) -> Result<()> {
        self.dispatch_transaction(
            parcel,
            false,
            target,
            code,
            flags,
            read_buffer,
            read_consumed,
        )
    }

    pub fn reply(
        &mut self,
        parcel: &mut Parcel,
        code: u32,
        flags: TransactionFlags,
        read_buffer: Option<&mut [u8]>,
        read_consumed: Option<&mut u64>,
    ) -> Result<()> {
        self.dispatch_transaction(
            parcel,
            true,
            u32::MAX,
            code,
            flags,
            read_buffer,
            read_consumed,
        )
    }

    define_binder_cmd!(enter_looper, BC_ENTER_LOOPER);
    define_binder_cmd!(exit_looper, BC_EXIT_LOOPER);
    define_binder_cmd!(free_transaction_buffer, BC_FREE_BUFFER, buffer_ptr : binder_uintptr_t);
    define_binder_cmd!(acquire, BC_ACQUIRE, handle : u32);
    define_binder_cmd!(release, BC_RELEASE, handle : u32);
    define_binder_cmd!(increfs, BC_INCREFS, handle : u32);
    define_binder_cmd!(decrefs, BC_DECREFS, handle : u32);
    define_binder_cmd!(register_death_notification, BC_REQUEST_DEATH_NOTIFICATION, handle: u32, cookie: binder_uintptr_t);
    define_binder_cmd!(dead_binder_done, BC_DEAD_BINDER_DONE, cookie: binder_uintptr_t);
}

impl Drop for BinderClient {
    fn drop(&mut self) {
        unsafe {
            munmap(NonNull::new(self.vmstart).unwrap(), self.vmsize).unwrap_unchecked();
        }
    }
}
