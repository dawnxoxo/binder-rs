#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use thiserror::Error;

pub mod binder;
pub mod binder_client;
pub mod parcel;

#[derive(Error, Debug)]
pub enum Error {
    #[error("transaction too big")]
    TxnTooBig,
}
