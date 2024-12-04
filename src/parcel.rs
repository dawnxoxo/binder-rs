use core::slice;
use std::{
    fmt,
    io::{Cursor, Error, Write},
};

use num_traits::ToBytes;

use crate::binder::binder_driver_command_protocol;

pub struct Parcel {
    cursor: Cursor<Vec<u8>>,
    object_offsets: Vec<usize>,
    buffers_size: u64,
}

impl fmt::Debug for Parcel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parcel")
            .field("data", &self.cursor.get_ref())
            .field("offsets", &self.object_offsets)
            .finish()
    }
}

impl Parcel {
    pub fn empty() -> Self {
        let data = vec![];
        Self {
            cursor: Cursor::new(data),
            object_offsets: vec![],
            buffers_size: 0,
        }
    }

    pub fn new(size: usize) -> Self {
        let data = Vec::with_capacity(size);

        Self {
            cursor: Cursor::new(data),
            object_offsets: vec![],
            buffers_size: 0,
        }
    }

    pub fn reset(&mut self) {
        self.cursor.set_position(0);
        self.cursor.get_mut().clear();
        self.object_offsets.clear();
    }

    pub fn position(&self) -> u64 {
        self.cursor.position()
    }

    pub fn set_position(&mut self, pos: u64) {
        self.cursor.set_position(pos)
    }

    pub fn append_parcel(&mut self, other: &mut Parcel) -> Result<(), Error> {
        let current_position = self.cursor.position();
        self.cursor.write_all(other.to_slice())?;
        for offset in &other.object_offsets {
            self.object_offsets.push(offset + current_position as usize);
        }
        Ok(())
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.cursor.get_ref().as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.cursor.get_mut().as_mut_ptr()
    }

    pub fn to_slice(&self) -> &[u8] {
        self.cursor.get_ref()
    }

    pub fn to_mut_slice(&mut self) -> &mut [u8] {
        self.cursor.get_mut()
    }

    pub fn len(&self) -> usize {
        self.cursor.get_ref().len()
    }

    pub fn buffers_size(&self) -> u64 {
        self.buffers_size
    }

    pub fn is_empty(&self) -> bool {
        self.cursor.get_ref().is_empty()
    }

    pub fn offsets_len(&self) -> usize {
        self.object_offsets.len()
    }

    pub fn offsets(&mut self) -> &mut Vec<usize> {
        &mut self.object_offsets
    }

    pub fn has_unread_data(&self) -> bool {
        self.cursor.position() != self.len() as u64
    }

    pub fn write_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        self.cursor.write_all(data)
    }

    pub fn write<T: ToBytes<Bytes = [u8; size_of::<T>()]>>(
        &mut self,
        data: T,
    ) -> Result<(), Error> {
        let mut buf = Vec::with_capacity(size_of::<T>());
        buf.copy_from_slice(&data.to_le_bytes());
        self.cursor.write_all(buf.as_ref())
    }

    pub fn write_object<T>(&mut self, object: T) -> Result<(), Error> {
        self.object_offsets.push(self.cursor.position() as usize);
        self.cursor.write(unsafe {
            slice::from_raw_parts(&object as *const _ as *const u8, size_of::<T>())
        })?;

        Ok(())
    }

    pub fn write_cmd(&mut self, cmd: binder_driver_command_protocol) -> Result<(), Error> {
        self.write(cmd as u32)
    }
}
