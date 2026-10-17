//! SMB2 negotiate request and response, with 3.1.1 negotiate contexts.
//!
//! MS-SMB2 2.2.3, 2.2.4, 2.2.3.1.

use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::dtyp::{FileTime, Guid, PosMarker, SizedWideString};

// ── NegotiateRequest (MS-SMB2 2.2.3) ───────────────────────────────

/// SMB2 NEGOTIATE Request.
///
/// MS-SMB2 2.2.3
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct NegotiateRequest {
    #[bw(calc = 36)]
    #[br(temp)]
    structure_size: u16,
    #[bw(try_calc(u16::try_from(dialects.len())))]
    #[br(temp)]
    dialect_count: u16,
    /// Security mode flags indicating signing requirements.
    pub security_mode: NegotiateSecurityMode,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u16,
    /// Client capabilities.
    pub capabilities: GlobalCapabilities,
    /// Client GUID.
    pub client_guid: Guid,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    negotiate_context_offset: PosMarker<u32>,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    #[br(temp)]
    negotiate_context_count: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u16,
    /// List of SMB dialects supported by the client.
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
    /// Negotiate contexts (SMB 3.1.1+ only).
    #[brw(if(dialects.contains(&Dialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

// ── NegotiateResponse (MS-SMB2 2.2.4) ──────────────────────────────

/// SMB2 NEGOTIATE Response.
///
/// MS-SMB2 2.2.4
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct NegotiateResponse {
    #[bw(calc = 65)]
    #[br(temp)]
    structure_size: u16,
    /// Server security mode.
    pub security_mode: NegotiateSecurityMode,
    /// Selected dialect revision.
    pub dialect_revision: NegotiateDialect,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    #[br(assert(if dialect_revision == NegotiateDialect::Smb0311 { negotiate_context_count > 0 } else { negotiate_context_count == 0 }))]
    #[br(temp)]
    negotiate_context_count: u16,
    /// Server GUID.
    pub server_guid: Guid,
    /// Server capabilities.
    pub capabilities: GlobalCapabilities,
    /// Maximum transaction size supported by the server.
    pub max_transact_size: u32,
    /// Maximum read size supported by the server.
    pub max_read_size: u32,
    /// Maximum write size supported by the server.
    pub max_write_size: u32,
    /// Current system time on the server.
    pub system_time: FileTime,
    /// Server start time.
    pub server_start_time: FileTime,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(try_calc(u16::try_from(buffer.len())))]
    #[br(temp)]
    security_buffer_length: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    negotiate_context_offset: PosMarker<u32>,
    /// Security buffer containing GSSAPI token.
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,
    /// Negotiate contexts (SMB 3.1.1+ only).
    #[brw(if(matches!(dialect_revision, NegotiateDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

// ── Bitfield types ────────────────────────────────────────────────

/// Negotiate security mode flags.
///
/// MS-SMB2 2.2.3
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NegotiateSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip]
    __: B14,
}

/// Global capabilities flags.
///
/// MS-SMB2 2.2.3
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct GlobalCapabilities {
    pub dfs: bool,
    pub leasing: bool,
    pub large_mtu: bool,
    pub multi_channel: bool,
    pub persistent_handles: bool,
    pub directory_leasing: bool,
    pub encryption: bool,
    pub notifications: bool,
    #[skip]
    __: B24,
}

// ── Dialect enums ─────────────────────────────────────────────────

/// SMB2/SMB3 protocol dialect revisions.
///
/// MS-SMB2 2.2.3
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[brw(repr(u16))]
pub enum Dialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311,
}

/// Dialects that may be used in the Negotiate Response.
///
/// MS-SMB2 2.2.4
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum NegotiateDialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311,
    Smb02Wildcard = 0x02FF,
}

// ── NegotiateContext (MS-SMB2 2.2.3.1) ─────────────────────────────

/// A single negotiate context item.
///
/// MS-SMB2 2.2.3.1
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct NegotiateContext {
    /// Type of the negotiate context.
    #[brw(align_before = 8)]
    pub context_type: NegotiateContextType,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    data_length: PosMarker<u16>,
    #[bw(calc = 0)]
    reserved: u32,
    /// Context-specific data.
    #[br(args(&context_type))]
    #[br(map_stream = |s| s.take_seek(data_length.value as u64))]
    #[br(pad_size_to = data_length.value)]
    #[bw(write_with = PosMarker::write_size, args(&data_length))]
    pub data: NegotiateContextValue,
}

/// Negotiate context type identifiers.
///
/// MS-SMB2 2.2.3.1
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(little)]
pub enum NegotiateContextType {
    #[brw(magic = 0x0001u16)]
    PreauthIntegrityCapabilities,
    #[brw(magic = 0x0002u16)]
    EncryptionCapabilities,
    #[brw(magic = 0x0003u16)]
    CompressionCapabilities,
    #[brw(magic = 0x0005u16)]
    NetnameNegotiateContextId,
    #[brw(magic = 0x0006u16)]
    TransportCapabilities,
    #[brw(magic = 0x0007u16)]
    RdmaTransformCapabilities,
    #[brw(magic = 0x0008u16)]
    SigningCapabilities,
    /// Any context type not recognized by this crate.
    Unknown(u16),
}

impl NegotiateContextType {
    /// The on-wire type ID.
    pub fn id(&self) -> u16 {
        match self {
            NegotiateContextType::PreauthIntegrityCapabilities => 0x0001,
            NegotiateContextType::EncryptionCapabilities => 0x0002,
            NegotiateContextType::CompressionCapabilities => 0x0003,
            NegotiateContextType::NetnameNegotiateContextId => 0x0005,
            NegotiateContextType::TransportCapabilities => 0x0006,
            NegotiateContextType::RdmaTransformCapabilities => 0x0007,
            NegotiateContextType::SigningCapabilities => 0x0008,
            NegotiateContextType::Unknown(id) => *id,
        }
    }
}

/// Negotiate context values.
///
/// MS-SMB2 2.2.3.1.1–2.2.3.1.7
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[br(import(context_type: &NegotiateContextType))]
pub enum NegotiateContextValue {
    #[br(pre_assert(context_type == &NegotiateContextType::PreauthIntegrityCapabilities))]
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::EncryptionCapabilities))]
    EncryptionCapabilities(EncryptionCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::CompressionCapabilities))]
    CompressionCapabilities(CompressionCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::NetnameNegotiateContextId))]
    NetnameNegotiateContextId(NetnameNegotiateContextId),
    #[br(pre_assert(context_type == &NegotiateContextType::TransportCapabilities))]
    TransportCapabilities(TransportCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::RdmaTransformCapabilities))]
    RdmaTransformCapabilities(RdmaTransformCapabilities),
    #[br(pre_assert(context_type == &NegotiateContextType::SigningCapabilities))]
    SigningCapabilities(SigningCapabilities),
    /// Raw data of an unrecognized context.
    #[br(pre_assert(matches!(context_type, NegotiateContextType::Unknown(_))))]
    Unknown {
        #[br(calc = context_type.id())]
        #[bw(ignore)]
        type_id: u16,
        #[br(parse_with = binrw::helpers::until_eof)]
        data: Vec<u8>,
    },
}

impl NegotiateContextValue {
    /// Gets the matching negotiate context type for this value.
    pub fn get_matching_type(&self) -> NegotiateContextType {
        match self {
            NegotiateContextValue::PreauthIntegrityCapabilities(_) => {
                NegotiateContextType::PreauthIntegrityCapabilities
            }
            NegotiateContextValue::EncryptionCapabilities(_) => {
                NegotiateContextType::EncryptionCapabilities
            }
            NegotiateContextValue::CompressionCapabilities(_) => {
                NegotiateContextType::CompressionCapabilities
            }
            NegotiateContextValue::NetnameNegotiateContextId(_) => {
                NegotiateContextType::NetnameNegotiateContextId
            }
            NegotiateContextValue::TransportCapabilities(_) => {
                NegotiateContextType::TransportCapabilities
            }
            NegotiateContextValue::RdmaTransformCapabilities(_) => {
                NegotiateContextType::RdmaTransformCapabilities
            }
            NegotiateContextValue::SigningCapabilities(_) => {
                NegotiateContextType::SigningCapabilities
            }
            NegotiateContextValue::Unknown { type_id, .. } => {
                NegotiateContextType::Unknown(*type_id)
            }
        }
    }
}

// From impls for constructing NegotiateContext from typed values.

impl From<PreauthIntegrityCapabilities> for NegotiateContext {
    fn from(val: PreauthIntegrityCapabilities) -> Self {
        NegotiateContext {
            context_type: NegotiateContextType::PreauthIntegrityCapabilities,
            data: NegotiateContextValue::PreauthIntegrityCapabilities(val),
        }
    }
}

impl From<EncryptionCapabilities> for NegotiateContext {
    fn from(val: EncryptionCapabilities) -> Self {
        NegotiateContext {
            context_type: NegotiateContextType::EncryptionCapabilities,
            data: NegotiateContextValue::EncryptionCapabilities(val),
        }
    }
}

impl From<SigningCapabilities> for NegotiateContext {
    fn from(val: SigningCapabilities) -> Self {
        NegotiateContext {
            context_type: NegotiateContextType::SigningCapabilities,
            data: NegotiateContextValue::SigningCapabilities(val),
        }
    }
}

impl From<CompressionCapabilities> for NegotiateContext {
    fn from(val: CompressionCapabilities) -> Self {
        NegotiateContext {
            context_type: NegotiateContextType::CompressionCapabilities,
            data: NegotiateContextValue::CompressionCapabilities(val),
        }
    }
}

impl From<TransportCapabilities> for NegotiateContext {
    fn from(val: TransportCapabilities) -> Self {
        NegotiateContext {
            context_type: NegotiateContextType::TransportCapabilities,
            data: NegotiateContextValue::TransportCapabilities(val),
        }
    }
}

// ── Context value structs ─────────────────────────────────────────

/// Pre-authentication integrity capabilities.
///
/// MS-SMB2 2.2.3.1.1
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct PreauthIntegrityCapabilities {
    #[bw(try_calc(u16::try_from(hash_algorithms.len())))]
    hash_algorithm_count: u16,
    #[bw(try_calc(u16::try_from(salt.len())))]
    salt_length: u16,
    #[br(count = hash_algorithm_count)]
    pub hash_algorithms: Vec<HashAlgorithm>,
    #[br(count = salt_length)]
    pub salt: Vec<u8>,
}

/// Hash algorithms for pre-authentication integrity.
///
/// MS-SMB2 2.2.3.1.1
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(little)]
pub enum HashAlgorithm {
    #[brw(magic = 0x0001u16)]
    Sha512,
    Unknown(u16),
}

impl HashAlgorithm {
    pub fn id(&self) -> u16 {
        match self {
            HashAlgorithm::Sha512 => 0x0001,
            HashAlgorithm::Unknown(id) => *id,
        }
    }
}

/// Encryption capabilities.
///
/// MS-SMB2 2.2.3.1.2
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct EncryptionCapabilities {
    #[bw(try_calc(u16::try_from(ciphers.len())))]
    cipher_count: u16,
    #[br(count = cipher_count)]
    pub ciphers: Vec<EncryptionCipher>,
}

/// Encryption cipher identifiers.
///
/// MS-SMB2 2.2.3.1.2
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(little)]
pub enum EncryptionCipher {
    #[brw(magic = 0x0001u16)]
    Aes128Ccm,
    #[brw(magic = 0x0002u16)]
    Aes128Gcm,
    #[brw(magic = 0x0003u16)]
    Aes256Ccm,
    #[brw(magic = 0x0004u16)]
    Aes256Gcm,
    Unknown(u16),
}

impl EncryptionCipher {
    pub fn id(&self) -> u16 {
        match self {
            EncryptionCipher::Aes128Ccm => 0x0001,
            EncryptionCipher::Aes128Gcm => 0x0002,
            EncryptionCipher::Aes256Ccm => 0x0003,
            EncryptionCipher::Aes256Gcm => 0x0004,
            EncryptionCipher::Unknown(id) => *id,
        }
    }
}

/// Compression capabilities.
///
/// MS-SMB2 2.2.3.1.3
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct CompressionCapabilities {
    #[bw(try_calc(u16::try_from(compression_algorithms.len())))]
    compression_algorithm_count: u16,
    #[bw(calc = 0)]
    _padding: u16,
    pub flags: CompressionCapsFlags,
    #[br(count = compression_algorithm_count)]
    pub compression_algorithms: Vec<CompressionAlgorithm>,
}

/// Compression algorithm identifiers.
///
/// MS-SMB2 2.2.3.1.3
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(little)]
pub enum CompressionAlgorithm {
    #[brw(magic = 0x0000u16)]
    None,
    #[brw(magic = 0x0001u16)]
    LZNT1,
    #[brw(magic = 0x0002u16)]
    LZ77,
    #[brw(magic = 0x0003u16)]
    LZ77Huffman,
    #[brw(magic = 0x0004u16)]
    PatternV1,
    #[brw(magic = 0x0005u16)]
    LZ4,
    Unknown(u16),
}

impl CompressionAlgorithm {
    pub fn id(&self) -> u16 {
        match self {
            CompressionAlgorithm::None => 0x0000,
            CompressionAlgorithm::LZNT1 => 0x0001,
            CompressionAlgorithm::LZ77 => 0x0002,
            CompressionAlgorithm::LZ77Huffman => 0x0003,
            CompressionAlgorithm::PatternV1 => 0x0004,
            CompressionAlgorithm::LZ4 => 0x0005,
            CompressionAlgorithm::Unknown(id) => *id,
        }
    }
}

/// Compression capability flags.
///
/// MS-SMB2 2.2.3.1.3
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CompressionCapsFlags {
    pub chained: bool,
    #[skip]
    __: B31,
}

/// Netname negotiate context.
///
/// MS-SMB2 2.2.3.1.4
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(little)]
pub struct NetnameNegotiateContextId {
    #[br(parse_with = parse_netname)]
    #[bw(write_with = write_netname)]
    pub netname: SizedWideString,
}

fn parse_netname<R: binrw::io::Read + binrw::io::Seek>(
    reader: &mut R,
    _endian: binrw::Endian,
    (): (),
) -> binrw::BinResult<SizedWideString> {
    let mut data = Vec::new();
    let mut byte = [0u8; 2];
    while match reader.read(&mut byte) {
        Ok(2) => {
            data.push(u16::from_le_bytes(byte));
            true
        }
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(e) => return Err(e.into()),
    } {}
    Ok(SizedWideString { data })
}

fn write_netname<W: binrw::io::Write + binrw::io::Seek>(
    netname: &SizedWideString,
    writer: &mut W,
    _endian: binrw::Endian,
    (): (),
) -> binrw::BinResult<()> {
    for c in &netname.data {
        writer.write_all(&c.to_le_bytes())?;
    }
    Ok(())
}

/// Transport capabilities.
///
/// MS-SMB2 2.2.3.1.5
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct TransportCapabilities {
    pub accept_transport_layer_security: bool,
    #[skip]
    __: B31,
}

/// RDMA transform capabilities.
///
/// MS-SMB2 2.2.3.1.6
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct RdmaTransformCapabilities {
    #[bw(try_calc(u16::try_from(transforms.len())))]
    transform_count: u16,
    _reserved1: u16,
    _reserved2: u32,
    #[br(count = transform_count)]
    pub transforms: Vec<RdmaTransformId>,
}

/// RDMA transform identifiers.
///
/// MS-SMB2 2.2.3.1.6
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum RdmaTransformId {
    None = 0x0000,
    Encryption = 0x0001,
    Signing = 0x0002,
}

/// Signing capabilities.
///
/// MS-SMB2 2.2.3.1.7
#[binrw::binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct SigningCapabilities {
    #[bw(try_calc(u16::try_from(signing_algorithms.len())))]
    signing_algorithm_count: u16,
    #[br(count = signing_algorithm_count)]
    pub signing_algorithms: Vec<SigningAlgorithmId>,
}

/// Signing algorithm identifiers.
///
/// MS-SMB2 2.2.3.1.7
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(little)]
pub enum SigningAlgorithmId {
    #[brw(magic = 0x0000u16)]
    HmacSha256,
    #[brw(magic = 0x0001u16)]
    AesCmac,
    #[brw(magic = 0x0002u16)]
    AesGmac,
    Unknown(u16),
}

impl SigningAlgorithmId {
    pub fn id(&self) -> u16 {
        match self {
            SigningAlgorithmId::HmacSha256 => 0x0000,
            SigningAlgorithmId::AesCmac => 0x0001,
            SigningAlgorithmId::AesGmac => 0x0002,
            SigningAlgorithmId::Unknown(id) => *id,
        }
    }
}

// ── Helper methods for getting contexts from negotiate messages ────

impl NegotiateRequest {
    /// Gets the preauth integrity capabilities context, if present.
    pub fn get_ctx_preauth_integrity_capabilities(&self) -> Option<&PreauthIntegrityCapabilities> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts.iter().find_map(|ctx| match &ctx.data {
                NegotiateContextValue::PreauthIntegrityCapabilities(c) => Some(c),
                _ => None,
            })
        })
    }

    /// Gets the encryption capabilities context, if present.
    pub fn get_ctx_encryption_capabilities(&self) -> Option<&EncryptionCapabilities> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts.iter().find_map(|ctx| match &ctx.data {
                NegotiateContextValue::EncryptionCapabilities(c) => Some(c),
                _ => None,
            })
        })
    }

    /// Gets the signing capabilities context, if present.
    pub fn get_ctx_signing_capabilities(&self) -> Option<&SigningCapabilities> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts.iter().find_map(|ctx| match &ctx.data {
                NegotiateContextValue::SigningCapabilities(c) => Some(c),
                _ => None,
            })
        })
    }

    /// Gets the transport capabilities context, if present.
    pub fn get_ctx_transport_capabilities(&self) -> Option<&TransportCapabilities> {
        self.negotiate_context_list.as_ref().and_then(|contexts| {
            contexts.iter().find_map(|ctx| match &ctx.data {
                NegotiateContextValue::TransportCapabilities(c) => Some(c),
                _ => None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_negotiate_request_roundtrip() {
        let req = NegotiateRequest {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            capabilities: GlobalCapabilities::new(),
            client_guid: Guid::from([7u8; 16]),
            dialects: vec![Dialect::Smb021],
            negotiate_context_list: None,
        };
        let mut buf = Cursor::new(Vec::new());
        req.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: NegotiateRequest = NegotiateRequest::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.dialects, vec![Dialect::Smb021]);
        assert_eq!(decoded.client_guid, Guid::from([7u8; 16]));
    }

    #[test]
    fn test_negotiate_response_roundtrip() {
        let resp = NegotiateResponse {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            dialect_revision: NegotiateDialect::Smb021,
            server_guid: Guid::from([0xabu8; 16]),
            capabilities: GlobalCapabilities::new(),
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: FileTime::ZERO,
            server_start_time: FileTime::ZERO,
            buffer: vec![0x60, 0x1c],
            negotiate_context_list: None,
        };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: NegotiateResponse = NegotiateResponse::read_le(&mut cursor).unwrap();
        assert_eq!(decoded.dialect_revision, NegotiateDialect::Smb021);
        assert_eq!(decoded.max_transact_size, 65536);
    }

    #[test]
    fn test_dialect_id() {
        assert_eq!(Dialect::Smb0311 as u16, 0x0311);
        assert_eq!(Dialect::Smb021 as u16, 0x0210);
    }

    #[test]
    fn test_encryption_cipher_id() {
        assert_eq!(EncryptionCipher::Aes128Gcm.id(), 0x0002);
        assert_eq!(EncryptionCipher::Aes128Ccm.id(), 0x0001);
    }
}
