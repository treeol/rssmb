//! SMB2 IOCTL request and response.
//!
//! MS-SMB2 2.2.31–2.2.32.

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::create::FileId;
use crate::dtyp::PosMarker;

/// SMB2 IOCTL Request.
///
/// MS-SMB2 2.2.31
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct IoctlRequest {
    #[bw(calc = 57)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _input_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _input_count: PosMarker<u32>,
    pub max_input_response: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _output_offset: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _output_count: u32,
    pub max_output_response: u32,
    pub flags: IoctlRequestFlags,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u32,
    #[bw(write_with = PosMarker::write_aoff_size, args(&_input_offset, &_input_count))]
    #[br(map_stream = |s| s.take_seek(_input_count.value as u64), args(ctl_code, flags))]
    pub buffer: IoctlReqData,
}

/// Flags for IOCTL request.
///
/// MS-SMB2 2.2.31
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct IoctlRequestFlags {
    pub is_fsctl: bool,
    #[skip]
    __: B31,
}

/// IOCTL request data — the FSCTL/IOCTL input buffer.
///
/// On the wire, the variant is selected by the ctl_code and flags.
/// Our server only handles FSCTL_PIPE_TRANSCEIVE and FSCTL_VALIDATE_NEGOTIATE_INFO;
/// everything else is treated as a raw Ioctl buffer.
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
#[br(import(ctl_code: u32, flags: IoctlRequestFlags))]
pub enum IoctlReqData {
    #[br(pre_assert(ctl_code == FsctlCodes::PipeTransceive as u32 && flags.is_fsctl()))]
    FsctlPipeTransceive(IoctlBuffer),
    #[br(pre_assert(ctl_code == FsctlCodes::ValidateNegotiateInfo as u32 && flags.is_fsctl()))]
    FsctlValidateNegotiateInfo(ValidateNegotiateInfoRequest),
    #[br(pre_assert(ctl_code == FsctlCodes::DfsGetReferrals as u32 && flags.is_fsctl()))]
    FsctlDfsGetReferrals(IoctlBuffer),
    #[br(pre_assert(ctl_code == FsctlCodes::DfsGetReferralsEx as u32 && flags.is_fsctl()))]
    FsctlDfsGetReferralsEx(IoctlBuffer),
    /// General, non-smb FSCTL ioctl buffer.
    Ioctl(IoctlBuffer),
}

impl IoctlReqData {
    pub fn get_size(&self) -> u32 {
        match self {
            IoctlReqData::FsctlPipeTransceive(b) => b.len() as u32,
            IoctlReqData::FsctlValidateNegotiateInfo(_) => 32,
            IoctlReqData::FsctlDfsGetReferrals(b) => b.len() as u32,
            IoctlReqData::FsctlDfsGetReferralsEx(b) => b.len() as u32,
            IoctlReqData::Ioctl(b) => b.len() as u32,
        }
    }
}

/// FSCTL codes used by the server.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum FsctlCodes {
    PipeTransceive = 0x0011_C017,
    ValidateNegotiateInfo = 0x0014_0204,
    DfsGetReferrals = 0x0006_0194,
    DfsGetReferralsEx = 0x0006_01B0,
    QueryNetworkInterfaceInfo = 0x0014_01FC,
}

/// Raw IOCTL buffer (raw bytes).
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct IoctlBuffer {
    #[br(parse_with = binrw::helpers::until_eof)]
    buffer: Vec<u8>,
}

impl From<Vec<u8>> for IoctlBuffer {
    fn from(buffer: Vec<u8>) -> Self {
        Self { buffer }
    }
}

impl From<&[u8]> for IoctlBuffer {
    fn from(buffer: &[u8]) -> Self {
        Self {
            buffer: buffer.to_vec(),
        }
    }
}

impl std::ops::Deref for IoctlBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl std::ops::DerefMut for IoctlBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

/// ValidateNegotiateInfo request (FSCTL_VALIDATE_NEGOTIATE_INFO).
///
/// MS-SMB2 2.2.31.6
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct ValidateNegotiateInfoRequest {
    pub capabilities: u32,
    pub guid: crate::dtyp::Guid,
    pub security_mode: crate::negotiate::NegotiateSecurityMode,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub dialects: Vec<DialectU16>,
}

/// Dialect list entry for VNI (u16).
#[binrw::binrw]
#[derive(Debug, Clone, Copy)]
#[brw(little)]
pub struct DialectU16 {
    pub dialect: u16,
}

/// ValidateNegotiateInfo response.
///
/// MS-SMB2 2.2.32.6
#[binrw::binrw]
#[brw(little)]
pub struct ValidateNegotiateInfoResponse {
    pub capabilities: u32,
    pub guid: crate::dtyp::Guid,
    pub security_mode: crate::negotiate::NegotiateSecurityMode,
    pub dialect: crate::negotiate::NegotiateDialect,
}

/// SMB2 IOCTL Response.
///
/// MS-SMB2 2.2.32
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct IoctlResponse {
    #[bw(calc = 49)]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    input_offset: PosMarker<u32>,
    #[bw(assert(in_buffer.is_empty()))]
    #[bw(try_calc = in_buffer.len().try_into())]
    #[br(assert(input_count == 0))]
    #[br(temp)]
    input_count: u32,
    #[br(assert(output_offset.value == 0 || output_offset.value == input_offset.value + input_count))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_offset: PosMarker<u32>,
    #[bw(try_calc = out_buffer.len().try_into())]
    #[br(temp)]
    output_count: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved1: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u32,
    #[br(seek_before = std::io::SeekFrom::Start(input_offset.value.into()))]
    #[br(count = input_count)]
    #[bw(write_with = PosMarker::write_aoff, args(&input_offset))]
    pub in_buffer: Vec<u8>,
    #[br(seek_before = std::io::SeekFrom::Start(output_offset.value.into()))]
    #[br(count = output_count)]
    #[bw(write_with = PosMarker::write_aoff, args(&output_offset))]
    pub out_buffer: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_buffer_from_vec() {
        let buf: IoctlBuffer = vec![1u8, 2, 3].into();
        assert_eq!(buf.len(), 3);
    }
}
