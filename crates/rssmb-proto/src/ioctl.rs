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

/// Network interface info entry (FSCTL_QUERY_NETWORK_INTERFACE_INFO).
///
/// MS-SMB2 2.2.32.5: each entry is a fixed 152-byte structure —
/// Next (4) + IfIndex (4) + Capability (4) + Reserved (4) + LinkSpeed (8) +
/// SockAddr_Storage (128). `Next` is the byte offset from the start of this
/// entry to the next entry; 0 for the last entry (152 for contiguous
/// non-terminal entries).
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct NetworkInterfaceInfo {
    /// Offset from the start of this structure to the next entry;
    /// 0 if this is the last entry.
    pub next: u32,
    /// Interface index (OS ifindex).
    pub if_index: u32,
    /// Capability flags (RSS / RDMA).
    pub capability: NetworkInterfaceCapabilityFlags,
    /// Reserved; written as zero.
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u32,
    /// Link speed in bits per second.
    pub link_speed: u64,
    /// SOCKADDR_STORAGE (128 bytes, Windows layout: family 2 = AF_INET,
    /// 23 = AF_INET6).
    pub sock_addr_storage: SockAddrStorage,
}

/// Total serialized size of one NETWORK_INTERFACE_INFO entry (MS-SMB2 2.2.32.5).
pub const NETWORK_INTERFACE_INFO_SIZE: usize = 152;

/// SOCKADDR_STORAGE for FSCTL_QUERY_NETWORK_INTERFACE_INFO (MS-SMB2 2.2.32.5).
///
/// Windows on-wire layout: Family (2 bytes; 2 = AF_INET, 23 = AF_INET6)
/// followed by family-specific data, zero-padded to 128 bytes total.
/// Family values are the *Windows* constants, not the platform's.
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct SockAddrStorage {
    /// Windows address family: 2 = AF_INET, 23 = AF_INET6.
    pub family: u16,
    #[br(count = 126)]
    #[bw(write_with = write_sockaddr_tail)]
    /// Family-specific bytes (rest of the 128-byte storage, zero-padded).
    pub tail: Vec<u8>,
}

/// Windows AF_INET (sockets family constant on the wire).
pub const AF_INET_WINDOWS: u16 = 2;
/// Windows AF_INET6 (sockets family constant on the wire).
pub const AF_INET6_WINDOWS: u16 = 23;

impl SockAddrStorage {
    /// Build the storage for an IPv4 address (Windows sockaddr_in layout:
    /// Family(2) + Port(2) + Address(4) + 8 zero bytes; rest zeroed).
    pub fn ipv4(addr: std::net::Ipv4Addr) -> Self {
        let mut tail = vec![0u8; 126];
        tail[2..6].copy_from_slice(&addr.octets());
        Self {
            family: AF_INET_WINDOWS,
            tail,
        }
    }

    /// Build the storage for an IPv6 address (Windows sockaddr_in6 layout:
    /// Family(2) + Port(2) + FlowInfo(4) + Address(16) + ScopeId(4); rest zeroed).
    pub fn ipv6(addr: std::net::Ipv6Addr, scope_id: u32) -> Self {
        let mut tail = vec![0u8; 126];
        // tail offsets (after the 2-byte family): port 0..2, flow info 2..6,
        // address 6..22, scope id 22..26.
        tail[6..22].copy_from_slice(&addr.octets());
        tail[22..26].copy_from_slice(&scope_id.to_le_bytes());
        Self {
            family: AF_INET6_WINDOWS,
            tail,
        }
    }

    /// Reconstruct the socket address, if the family is recognized.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self.family {
            AF_INET_WINDOWS => {
                if self.tail.len() < 6 {
                    return None;
                }
                let octets: [u8; 4] = self.tail[2..6].try_into().ok()?;
                Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(octets),
                    0,
                )))
            }
            AF_INET6_WINDOWS => {
                if self.tail.len() < 26 {
                    return None;
                }
                let octets: [u8; 16] = self.tail[6..22].try_into().ok()?;
                let scope_id = u32::from_le_bytes(self.tail[22..26].try_into().ok()?);
                Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(octets),
                    0,
                    0,
                    scope_id,
                )))
            }
            _ => None,
        }
    }
}

/// binrw writer helper: write the sockaddr tail padded to exactly 126 bytes.
#[allow(clippy::ptr_arg)] // binrw write_with passes the field by reference
fn write_sockaddr_tail<W: std::io::Write + std::io::Seek>(
    tail: &Vec<u8>,
    writer: &mut W,
    _endian: binrw::Endian,
    (): (),
) -> binrw::BinResult<()> {
    debug_assert!(tail.len() <= 126);
    writer.write_all(&tail[..tail.len().min(126)])?;
    let pad = 126usize.saturating_sub(tail.len());
    writer.write_all(&vec![0u8; pad])?;
    Ok(())
}

/// Serialize a list of NETWORK_INTERFACE_INFO entries with correct `Next`
/// offsets (152 for all but the last entry, 0 for the last).
pub fn serialize_network_interface_list(interfaces: &[NetworkInterfaceInfo]) -> Vec<u8> {
    use binrw::BinWrite;
    let mut buf = std::io::Cursor::new(Vec::new());
    for (i, iface) in interfaces.iter().enumerate() {
        let next = if i + 1 < interfaces.len() {
            NETWORK_INTERFACE_INFO_SIZE as u32
        } else {
            0
        };
        let mut entry = iface.clone();
        entry.next = next;
        // Serialization cannot fail with an in-memory cursor.
        let _ = entry.write_le(&mut buf);
    }
    buf.into_inner()
}

/// Network interface capability flags.
///
/// MS-SMB2 2.2.32.5
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NetworkInterfaceCapabilityFlags {
    pub rss: bool,
    pub rdma: bool,
    #[skip]
    __: B30,
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
    use binrw::io::Cursor;
    use std::io::Seek;

    #[test]
    fn test_ioctl_buffer_from_vec() {
        let buf: IoctlBuffer = vec![1u8, 2, 3].into();
        assert_eq!(buf.len(), 3);
    }

    /// Golden-byte test: single IPv4 entry (192.168.1.10, ifindex 3).
    ///
    /// Independently specified from MS-SMB2 2.2.32.5:
    /// Next=0 (last), IfIndex=3, Capability=0, Reserved=0, LinkSpeed,
    /// SockAddr_Storage = Family(2) + Port(0) + 4 address bytes + 120 zero
    /// bytes. Total 152 bytes.
    #[test]
    fn test_network_interface_info_ipv4_golden() {
        let iface = NetworkInterfaceInfo {
            next: 0,
            if_index: 3,
            capability: NetworkInterfaceCapabilityFlags::new(),
            link_speed: 1_000_000_000,
            sock_addr_storage: SockAddrStorage::ipv4("192.168.1.10".parse().unwrap()),
        };
        let bytes = serialize_network_interface_list(&[iface]);
        assert_eq!(bytes.len(), NETWORK_INTERFACE_INFO_SIZE);
        // Next = 0 (last entry)
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
        // IfIndex = 3
        assert_eq!(&bytes[4..8], &[3, 0, 0, 0]);
        // Capability = 0
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
        // Reserved = 0
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        // LinkSpeed = 1 Gbit/s (bytes 16..24)
        assert_eq!(&bytes[16..24], &1_000_000_000u64.to_le_bytes());
        // SockAddr_Storage starts at 24: family = 2 (AF_INET, little-endian)
        assert_eq!(&bytes[24..26], &[0x02, 0x00]);
        // Port = 0
        assert_eq!(&bytes[26..28], &[0, 0]);
        // Address at sockaddr offset 4..8 (entry bytes 28..32)
        assert_eq!(&bytes[28..32], &[192, 168, 1, 10]);
        // Remaining 120 bytes zero
        assert!(bytes[32..].iter().all(|&b| b == 0));
    }

    /// Golden-byte test: single IPv6 entry (fe80::1 scope 5, ifindex 7).
    ///
    /// SockAddr_Storage = Family(23) + Port(0) + FlowInfo(0) + 16 address
    /// bytes + ScopeId(4) + 100 zero bytes.
    #[test]
    fn test_network_interface_info_ipv6_golden() {
        let iface = NetworkInterfaceInfo {
            next: 0,
            if_index: 7,
            capability: NetworkInterfaceCapabilityFlags::new(),
            link_speed: 10_000_000_000,
            sock_addr_storage: SockAddrStorage::ipv6("fe80::1".parse().unwrap(), 5),
        };
        let bytes = serialize_network_interface_list(&[iface]);
        assert_eq!(bytes.len(), NETWORK_INTERFACE_INFO_SIZE);
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]); // Next = 0 (last)
        assert_eq!(&bytes[4..8], &[7, 0, 0, 0]); // IfIndex
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]); // Capability = 0
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]); // Reserved = 0
        assert_eq!(&bytes[16..24], &10_000_000_000u64.to_le_bytes());
        assert_eq!(&bytes[24..26], &[0x17, 0x00]); // family 23 = AF_INET6
        assert_eq!(&bytes[26..28], &[0, 0]); // Port = 0
        assert_eq!(&bytes[28..32], &[0, 0, 0, 0]); // FlowInfo = 0
                                                   // Address at sockaddr offset 8..24 (entry bytes 32..48)
        let expected_addr: [u8; 16] = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        assert_eq!(&bytes[32..48], &expected_addr);
        // ScopeId at sockaddr offset 24..28 (entry bytes 48..52) = 5
        assert_eq!(&bytes[48..52], &[5, 0, 0, 0]);
        assert!(bytes[52..].iter().all(|&b| b == 0));
    }

    /// Golden-byte test: capability bit positions (RSS = bit 0, RDMA = bit 1).
    /// Pins the bitfield order before anyone flips a flag on.
    #[test]
    fn test_network_interface_info_capability_bits_golden() {
        let iface = NetworkInterfaceInfo {
            next: 0,
            if_index: 1,
            capability: NetworkInterfaceCapabilityFlags::new().with_rss(true),
            link_speed: 0,
            sock_addr_storage: SockAddrStorage::ipv4("10.0.0.1".parse().unwrap()),
        };
        let bytes = serialize_network_interface_list(&[iface]);
        assert_eq!(&bytes[8..12], &[0x01, 0, 0, 0], "RSS must be bit 0");

        let iface = NetworkInterfaceInfo {
            next: 0,
            if_index: 1,
            capability: NetworkInterfaceCapabilityFlags::new().with_rdma(true),
            link_speed: 0,
            sock_addr_storage: SockAddrStorage::ipv4("10.0.0.1".parse().unwrap()),
        };
        let bytes = serialize_network_interface_list(&[iface]);
        assert_eq!(&bytes[8..12], &[0x02, 0, 0, 0], "RDMA must be bit 1");
    }

    /// Nonzero IPv6 scope id must survive a serialize/parse roundtrip.
    #[test]
    fn test_sockaddr_ipv6_scope_roundtrip() {
        let storage = SockAddrStorage::ipv6("2001:db8::1".parse().unwrap(), 42);
        let iface = NetworkInterfaceInfo {
            next: 0,
            if_index: 9,
            capability: NetworkInterfaceCapabilityFlags::new(),
            link_speed: 0,
            sock_addr_storage: storage,
        };
        let bytes = serialize_network_interface_list(&[iface]);
        let mut cursor = Cursor::new(&bytes[..]);
        let parsed: NetworkInterfaceInfo = NetworkInterfaceInfo::read_le(&mut cursor).unwrap();
        let addr = parsed.sock_addr_storage.socket_addr().unwrap();
        match addr {
            std::net::SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 42),
            other => panic!("expected v6, got {other}"),
        }
    }

    /// Two-entry chain: first Next = 152, last Next = 0; total 304 bytes.
    #[test]
    fn test_network_interface_info_two_entry_chain() {
        let ifaces = vec![
            NetworkInterfaceInfo {
                next: 0, // corrected by the serializer
                if_index: 1,
                capability: NetworkInterfaceCapabilityFlags::new(),
                link_speed: 0,
                sock_addr_storage: SockAddrStorage::ipv4("10.0.0.1".parse().unwrap()),
            },
            NetworkInterfaceInfo {
                next: 99, // garbage — corrected by the serializer
                if_index: 2,
                capability: NetworkInterfaceCapabilityFlags::new(),
                link_speed: 0,
                sock_addr_storage: SockAddrStorage::ipv4("10.0.0.2".parse().unwrap()),
            },
        ];
        let bytes = serialize_network_interface_list(&ifaces);
        assert_eq!(bytes.len(), 2 * NETWORK_INTERFACE_INFO_SIZE);
        assert_eq!(&bytes[0..4], &152u32.to_le_bytes()); // first Next
        assert_eq!(&bytes[152..156], &[0, 0, 0, 0]); // last Next
        assert_eq!(&bytes[152 + 4..152 + 8], &[2, 0, 0, 0]); // second IfIndex
    }

    /// Roundtrip: parse a serialized entry back and reconstruct the address.
    #[test]
    fn test_network_interface_info_roundtrip() {
        let ifaces = vec![
            NetworkInterfaceInfo {
                next: 0,
                if_index: 3,
                capability: NetworkInterfaceCapabilityFlags::new(),
                link_speed: 42,
                sock_addr_storage: SockAddrStorage::ipv4("192.168.1.10".parse().unwrap()),
            },
            NetworkInterfaceInfo {
                next: 0,
                if_index: 7,
                capability: NetworkInterfaceCapabilityFlags::new(),
                link_speed: 43,
                sock_addr_storage: SockAddrStorage::ipv6("2001:db8::1".parse().unwrap(), 0),
            },
        ];
        let bytes = serialize_network_interface_list(&ifaces);
        // Parse each 152-byte entry independently.
        let mut cursor = Cursor::new(&bytes[..]);
        let first: NetworkInterfaceInfo = NetworkInterfaceInfo::read_le(&mut cursor).unwrap();
        assert_eq!(first.if_index, 3);
        assert_eq!(
            first.sock_addr_storage.socket_addr(),
            Some("192.168.1.10:0".parse().unwrap())
        );
        cursor.seek(std::io::SeekFrom::Start(152)).unwrap();
        let second: NetworkInterfaceInfo = NetworkInterfaceInfo::read_le(&mut cursor).unwrap();
        assert_eq!(second.if_index, 7);
        assert_eq!(
            second.sock_addr_storage.socket_addr(),
            Some("[2001:db8::1]:0".parse().unwrap())
        );
    }
}
