//! SMB2 tree connect and disconnect messages.
//!
//! MS-SMB2 2.2.9–2.2.12.

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::dtyp::{PosMarker, SizedWideString, SizedStringSize};

/// SMB2 TREE_CONNECT Request.
///
/// MS-SMB2 2.2.9 (base variant; extension contexts not implemented).
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct TreeConnectRequest {
    #[bw(calc = 9)]
    #[br(temp)]
    structure_size: u16,
    /// Flags indicating how to process the operation.
    pub flags: TreeConnectRequestFlags,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.size_bytes().try_into())]
    #[br(temp)]
    path_length: u16,
    /// Full share path name in Unicode format "\\server\share".
    #[br(args { size: SizedStringSize::Bytes(path_length as u32) })]
    #[bw(write_with = PosMarker::write_aoff, args(&_path_offset))]
    pub buffer: SizedWideString,
}

/// Flags for TREE_CONNECT request.
///
/// MS-SMB2 2.2.9
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct TreeConnectRequestFlags {
    pub cluster_reconnect: bool,
    pub redirect_to_owner: bool,
    pub extension_present: bool,
    #[skip]
    __: B13,
}

/// SMB2 TREE_CONNECT Response.
///
/// MS-SMB2 2.2.10
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct TreeConnectResponse {
    #[bw(calc = 16)]
    structure_size: u16,
    /// Type of share being accessed.
    pub share_type: ShareType,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u8,
    /// Properties for this share.
    pub share_flags: ShareFlags,
    /// Capabilities for this share.
    pub capabilities: TreeCapabilities,
    /// Maximal access for the user.
    pub maximal_access: u32,
}

/// Type of share being accessed.
///
/// MS-SMB2 2.2.10
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum ShareType {
    Disk = 0x1,
    Pipe = 0x2,
    Print = 0x3,
}

impl Default for ShareType {
    fn default() -> Self {
        ShareType::Disk
    }
}

/// Share flags indicating various share properties.
///
/// MS-SMB2 2.2.10
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ShareFlags {
    pub dfs: bool,
    pub dfs_root: bool,
    #[skip]
    __: B2,
    pub caching_mode: B4,
    pub restrict_exclusive_opens: bool,
    pub force_shared_delete: bool,
    pub allow_namespace_caching: bool,
    pub access_based_directory_enum: bool,
    pub force_levelii_oplock: bool,
    pub enable_hash_v1: bool,
    pub enable_hash_v2: bool,
    pub encrypt_data: bool,
    #[skip]
    __: B2,
    pub identity_remoting: bool,
    #[skip]
    __: B1,
    pub compress_data: bool,
    pub isolated_transport: bool,
    #[skip]
    __: B10,
}

/// Tree capabilities.
///
/// MS-SMB2 2.2.10
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct TreeCapabilities {
    #[skip]
    __: B3,
    pub dfs: bool,
    pub continuous_availability: bool,
    pub scaleout: bool,
    pub cluster: bool,
    pub asymmetric: bool,
    pub redirect_to_owner: bool,
    #[skip]
    __: B23,
}

/// SMB2 TREE_DISCONNECT Request.
///
/// MS-SMB2 2.2.11
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct TreeDisconnectRequest {
    #[bw(calc = 4)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
}

/// SMB2 TREE_DISCONNECT Response.
///
/// MS-SMB2 2.2.12
#[binrw::binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(little)]
pub struct TreeDisconnectResponse {
    #[bw(calc = 4)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_tree_connect_request_roundtrip() {
        let req = TreeConnectRequest {
            flags: TreeConnectRequestFlags::new(),
            buffer: SizedWideString::from_str(r"\\server\share"),
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: TreeConnectRequest = TreeConnectRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.buffer.to_string(), r"\\server\share");
    }

    #[test]
    fn test_tree_connect_response_roundtrip() {
        let resp = TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::new().with_encrypt_data(true),
            capabilities: TreeCapabilities::new(),
            maximal_access: 0x001f_01ff,
            ..Default::default()
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: TreeConnectResponse = TreeConnectResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.share_type, ShareType::Disk);
        assert_eq!(decoded.maximal_access, 0x001f_01ff);
        assert!(decoded.share_flags.encrypt_data());
    }
}