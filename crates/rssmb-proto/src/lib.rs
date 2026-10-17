//! RSSMB SMB2/3 wire protocol types.
//!
//! Server-side encode/decode for SMB2 message structs. This crate
//! replaces the smb-rs `smb-msg`, `smb-dtyp`, and `smb-fscc` crates.
//!
//! Wire layout references: MS-SMB2 (protocol), MS-FSCC (file/FS info
//! structures), MS-DTYP (basic types).
//
// The `#[bitfield]` macro (modular_bitfield) generates code that triggers
// `unused_parens` warnings. Silence them at the crate level rather than
// fighting macro-generated code.
#![allow(unused_parens)]

pub mod cancel;
pub mod create;
pub mod dtyp;
pub mod echo;
pub mod error;
pub mod file;
pub mod fscc;
pub mod header;
pub mod info;
pub mod ioctl;
pub mod lock;
pub mod negotiate;
pub mod notify;
pub mod oplock;
pub mod plain;
pub mod query_dir;
pub mod session_setup;
pub mod tree_connect;

pub use cancel::CancelRequest;
pub use dtyp::{
    Boolean, FileTime, FixedWideString, Guid, PosMarker, SizedStringSize, SizedWideString,
};
pub use echo::{EchoRequest, EchoResponse};
pub use error::ErrorResponse;
pub use fscc::{
    FileAttributes, FileBasicInformation, FileDispositionInformation, FileEndOfFileInformation,
    FileFsSectorSizeInformation, FileRenameInformation, FileStreamInformation, SectorSizeInfoFlags,
    StreamType,
};
pub use header::{Command, Header, HeaderFlags};
pub use plain::{PlainRequest, PlainResponse, RequestContent, ResponseContent};
