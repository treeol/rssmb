//! RSSMB SMB2/3 wire protocol types.
//!
//! Server-side encode/decode for SMB2 message structs. This crate
//! replaces the smb-rs `smb-msg`, `smb-dtyp`, and `smb-fscc` crates.
//!
//! Wire layout references: MS-SMB2 (protocol), MS-FSCC (file/FS info
//! structures), MS-DTYP (basic types).

pub mod dtyp;
pub mod fscc;
pub mod header;
pub mod echo;
pub mod cancel;
pub mod error;
pub mod negotiate;
pub mod session_setup;
pub mod tree_connect;
pub mod create;
pub mod file;
pub mod oplock;
pub mod info;
pub mod query_dir;
pub mod notify;
pub mod ioctl;
pub mod plain;

pub use dtyp::{Guid, FileTime, Boolean, PosMarker, SizedWideString, SizedStringSize};
pub use fscc::{
    FileAttributes, FileBasicInformation, FileEndOfFileInformation,
    FileDispositionInformation, FileRenameInformation,
    FileFsSectorSizeInformation, SectorSizeInfoFlags,
};
pub use header::{Header, Command, HeaderFlags};
pub use echo::{EchoRequest, EchoResponse};
pub use cancel::CancelRequest;
pub use error::ErrorResponse;
pub use plain::{PlainRequest, PlainResponse, RequestContent, ResponseContent};