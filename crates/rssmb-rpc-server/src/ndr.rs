//! NDR20 (Network Data Representation) encoder/decoder for SrvSvc.
//!
//! Hand-written for the specific structures needed by Step 8:
//! NetrShareEnum (opnum 15), NetrShareGetInfo (16), NetrServerGetInfo (21).
//! Only little-endian NDR20 is supported.

use super::{ShareInfo};

// --- WERROR codes ---
pub const WERR_SUCCESS: u32 = 0;
pub const WERR_INVALID_LEVEL: u32 = 124;
pub const WERR_NERR_NETNAMENOTFOUND: u32 = 2310;
pub const WERR_INVALID_PARAM: u32 = 87;

// --- Share types ---
pub const STYPE_DISKTREE: u32 = 0;
pub const STYPE_IPC: u32 = 0x80000000;
pub const STYPE_SPECIAL: u32 = 0x80000000;
pub const STYPE_IPC_SPECIAL: u32 = 0x80000003;

/// NDR20 encoder. Writes little-endian primitives with alignment.
pub struct NdrWriter {
    buf: Vec<u8>,
}

impl NdrWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Align to `align` bytes from the start of the stream.
    fn align(&mut self, align: usize) {
        let pos = self.buf.len();
        let pad = (align - (pos % align)) % align;
        self.buf.resize(pos + pad, 0);
    }

    /// Write a u16 with 2-byte alignment.
    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a u32 with 4-byte alignment.
    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a raw u8 (no alignment).
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a unique pointer (NDR pointer_t). In NDR20, a unique pointer is
    /// a u32 where 0 = NULL and nonzero = a pointer ID (we use 1 for non-null).
    /// The actual referent data is written by the caller after the fixed part.
    pub fn write_unique_ptr(&mut self, is_present: bool) -> u32 {
        let ptr = if is_present { 1 } else { 0 };
        self.write_u32(ptr);
        ptr
    }

    /// Write a conformant varying array of wchar_t (UTF-16LE) string.
    /// This is a `WCHAR *` in NDR. The string includes a trailing NUL.
    /// For a unique pointer string, the pointer is written separately
    /// and this function writes the conformant array + data.
    pub fn write_wstr_conformant(&mut self, s: &str) {
        // Conformant varying array: max_count, offset, actual_count
        // The string is UTF-16LE with a trailing NUL.
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let total = utf16.len() as u32 + 1; // +1 for NUL
        self.write_u32(total); // max_count (conformant)
        self.write_u32(0); // offset (first index)
        self.write_u32(total); // actual_count
        for &ch in &utf16 {
            self.write_u16(ch);
        }
        self.write_u16(0); // NUL terminator
        // Pad to 4-byte boundary.
        let pad = (4 - (self.buf.len() % 4)) % 4;
        for _ in 0..pad {
            self.buf.push(0);
        }
    }

    /// Write a conformant array of u8 (for raw byte buffers).
    pub fn write_byte_array_conformant(&mut self, data: &[u8]) {
        self.write_u32(data.len() as u32); // max_count
        self.buf.extend_from_slice(data);
        // Pad to 4-byte boundary.
        let pad = (4 - (self.buf.len() % 4)) % 4;
        for _ in 0..pad {
            self.buf.push(0);
        }
    }
}

/// NDR20 decoder. Reads little-endian primitives with alignment.
pub struct NdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn align(&mut self, align: usize) {
        let pad = (align - (self.pos % align)) % align;
        self.pos += pad;
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        self.align(2);
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        self.align(4);
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Some(v)
    }

    /// Read a unique pointer (u32). Returns Some(true) if non-null.
    pub fn read_unique_ptr(&mut self) -> Option<bool> {
        let ptr = self.read_u32()?;
        Some(ptr != 0)
    }

    /// Read a conformant varying wchar_t string (NUL-terminated).
    /// Skips the data (doesn't return it — we only need to consume it).
    pub fn skip_wstr_conformant(&mut self) -> Option<()> {
        let max_count = self.read_u32()?;
        let _offset = self.read_u32()?;
        let actual_count = self.read_u32()?;
        // Each char is 2 bytes (u16).
        self.align(2);
        self.pos += (actual_count as usize) * 2;
        // Pad to 4-byte boundary.
        let pad = (4 - (self.pos % 4)) % 4;
        self.pos += pad;
        let _ = max_count;
        Some(())
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// SHARE_INFO_1 structure: {netname (wstr), type (u32), remark (wstr)}
pub fn encode_share_info_1(w: &mut NdrWriter, share: &ShareInfo) {
    // netname: unique pointer to conformant wstr
    let netname_ptr = w.write_unique_ptr(true);
    // type: u32
    w.write_u32(share.share_type);
    // remark: unique pointer to conformant wstr
    let remark_ptr = w.write_unique_ptr(!share.comment.is_empty());

    // Deferred pointees: netname, then remark (in order of appearance).
    if netname_ptr != 0 {
        w.write_wstr_conformant(&share.name);
    }
    if remark_ptr != 0 {
        w.write_wstr_conformant(&share.comment);
    }
}

/// Encode a NetrShareEnum response (opnum 15, level 1).
///
/// NDR20 layout:
/// ```text
/// SHARE_ENUM_STRUCT:
///   Level (u32) = 1
///   ShareInfoUnionPtr (u32) = nonzero
/// SHARE_INFO_1_CONTAINER (deferred):
///   EntriesRead (u32) = N
///   BufferPtr (u32) = nonzero (points to conformant array)
/// Conformant array (deferred):
///   MaxCount (u32) = N
///   N × SHARE_INFO_1 (inline):
///     NetnamePtr (u32) = nonzero (unique)
///     Type (u32) = share_type
///     RemarkPtr (u32) = 0 or nonzero (unique)
///   Deferred netname strings (in order)
///   Deferred remark strings (in order)
/// TotalEntries (u32) = N
/// ResumeHandlePtr (u32) = 0 (null)
/// WERROR (u32) = 0
/// ```
pub fn encode_netr_share_enum_response(
    shares: &[ShareInfo],
    level: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    let count = shares.len() as u32;

    // SHARE_ENUM_STRUCT: Level (u32) + SHARE_ENUM_UNION {tag (u32), ptr (u32)}
    w.write_u32(level); // Level (switch_is)
    w.write_u32(level); // Union tag (discriminant)
    let container_present = w.write_unique_ptr(!shares.is_empty());

    if container_present != 0 {
        // SHARE_INFO_1_CONTAINER: EntriesRead (u32) + BufferPtr (u32)
        w.write_u32(count);
        let buffer_present = w.write_unique_ptr(!shares.is_empty());

        if buffer_present != 0 {
            // Conformant array: MaxCount (u32)
            w.write_u32(count);
            // N × SHARE_INFO_1 (inline) — fixed parts first, pointers deferred
            let mut netname_ptrs: Vec<u32> = Vec::with_capacity(shares.len());
            let mut remark_ptrs: Vec<u32> = Vec::with_capacity(shares.len());
            for share in shares.iter() {
                let np = w.write_unique_ptr(true);
                w.write_u32(share.share_type);
                let rp = w.write_unique_ptr(!share.comment.is_empty());
                netname_ptrs.push(np);
                remark_ptrs.push(rp);
            }
            // Deferred netname strings (in order)
            for (i, share) in shares.iter().enumerate() {
                if netname_ptrs[i] != 0 {
                    w.write_wstr_conformant(&share.name);
                }
            }
            // Deferred remark strings (in order)
            for (i, share) in shares.iter().enumerate() {
                if remark_ptrs[i] != 0 {
                    w.write_wstr_conformant(&share.comment);
                }
            }
        }
    }

    // TotalEntries
    w.write_u32(count);
    // ResumeHandle (null)
    w.write_unique_ptr(false);
    // WERROR
    w.write_u32(WERR_SUCCESS);

    w.into_vec()
}

/// Encode a NetrShareGetInfo response (opnum 16, level 1).
/// Returns a SHARE_INFO_1 for the named share, or WERR_NERR_NETNAMENOTFOUND.
pub fn encode_netr_share_get_info_response(
    share: Option<&ShareInfo>,
    level: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();

    if let Some(s) = share {
        // SHARE_INFO_STRUCT: Level (u32) + SHARE_INFO_UNION {tag (u32), ptr (u32)}
        w.write_u32(level); // Level (switch_is)
        w.write_u32(level); // Union tag (discriminant)
        let info_ptr = w.write_unique_ptr(true); // union ptr
        if info_ptr != 0 {
            // SHARE_INFO_1 fixed part
            let np = w.write_unique_ptr(true);
            w.write_u32(s.share_type);
            let rp = w.write_unique_ptr(!s.comment.is_empty());
            // Deferred: netname
            if np != 0 {
                w.write_wstr_conformant(&s.name);
            }
            // Deferred: remark
            if rp != 0 {
                w.write_wstr_conformant(&s.comment);
            }
        }
        // WERROR
        w.write_u32(WERR_SUCCESS);
    } else {
        // No share found — null union pointer.
        w.write_u32(level);
        w.write_u32(level); // tag
        w.write_unique_ptr(false);
        w.write_u32(WERR_NERR_NETNAMENOTFOUND);
    }

    w.into_vec()
}

/// Encode a NetrServerGetInfo response (opnum 21, level 100).
/// SERVER_INFO_100: {sv100_platform_id (u32), sv100_name (wstr)}
pub fn encode_netr_server_get_info_response(
    server_name: &str,
    level: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();

    match level {
        100 => {
            // union pointer → SERVER_INFO_100
            let info_ptr = w.write_unique_ptr(true);
            w.write_u32(level); // switch_is
            if info_ptr != 0 {
                w.write_u32(500); // sv100_platform_id = PLATFORM_ID_NT
                let _name_ptr = w.write_unique_ptr(true); // sv100_name (unique wstr)
                w.write_wstr_conformant(server_name);
            }
            w.write_u32(WERR_SUCCESS);
        }
        101 => {
            // SERVER_INFO_101: platform_id, name, version_major, version_minor,
            // type, comment
            let info_ptr = w.write_unique_ptr(true);
            w.write_u32(level);
            if info_ptr != 0 {
                w.write_u32(500); // sv101_platform_id
                let _name_ptr = w.write_unique_ptr(true);
                w.write_u32(0x000a0000); // sv101_version_major:minor (10.0)
                w.write_u32(0x00000003); // sv101_type: SV_TYPE_SERVER | SV_TYPE_NT | SV_TYPE_WORKSTATION
                let _comment_ptr = w.write_unique_ptr(false); // no comment
                // Deferred: name
                w.write_wstr_conformant(server_name);
                // No comment (null pointer)
            }
            w.write_u32(WERR_SUCCESS);
        }
        _ => {
            // Unsupported level
            w.write_unique_ptr(false);
            w.write_u32(level);
            w.write_u32(WERR_INVALID_LEVEL);
        }
    }

    w.into_vec()
}

/// Parse the NetrShareEnum request stub to extract the level.
/// Returns (level, pref_max_len) or None if unparseable.
pub fn parse_netr_share_enum_request(stub: &[u8]) -> Option<(u32, u32)> {
    let mut r = NdrReader::new(stub);
    // ServerName: unique pointer
    let server_present = r.read_unique_ptr()?;
    if server_present {
        r.skip_wstr_conformant()?;
    }
    // InfoStruct: Level (u32) + union pointer (u32)
    let level = r.read_u32()?;
    let _union_ptr = r.read_u32()?;
    // PreferedMaximumLength (u32)
    let pref_max_len = r.read_u32().unwrap_or(0);
    // ResumeHandle: unique pointer (u32)
    let _resume_ptr = r.read_u32().unwrap_or(0);
    Some((level, pref_max_len))
}

/// Parse the NetrShareGetInfo request stub to extract the level and share name.
/// Returns (level, share_name) or None if unparseable.
pub fn parse_netr_share_get_info_request(stub: &[u8]) -> Option<(u32, String)> {
    let mut r = NdrReader::new(stub);
    // ServerName: unique pointer
    let server_present = r.read_unique_ptr()?;
    if server_present {
        r.skip_wstr_conformant()?;
    }
    // NetName: reference pointer (always present) to conformant wstr
    let _netname_ptr = r.read_u32()?; // reference pointer (always non-null)
    // Read the conformant wstr (max_count, offset, actual_count, chars...)
    let max_count = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual_count = r.read_u32()?;
    r.align(2);
    let mut name_bytes = Vec::new();
    for _ in 0..actual_count {
        let ch = r.read_u16()?;
        name_bytes.push(ch);
    }
    // Strip NUL terminator.
    let name: String = String::from_utf16_lossy(&name_bytes)
        .trim_end_matches('\0')
        .to_string();
    // Pad to 4-byte boundary.
    let pad = (4 - (r.pos % 4)) % 4;
    r.pos += pad;
    let _ = max_count;
    // Level (u32)
    let level = r.read_u32()?;
    Some((level, name))
}

/// Parse the NetrServerGetInfo request stub to extract the level.
/// Returns (level,) or None if unparseable.
pub fn parse_netr_server_get_info_request(stub: &[u8]) -> Option<u32> {
    let mut r = NdrReader::new(stub);
    // ServerName: unique pointer
    let server_present = r.read_unique_ptr()?;
    if server_present {
        r.skip_wstr_conformant()?;
    }
    // Level (u32)
    let level = r.read_u32()?;
    Some(level)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shares() -> Vec<ShareInfo> {
        vec![
            ShareInfo {
                name: "public".to_string(),
                comment: "Public share".to_string(),
                share_type: 0,
                encrypt_data: false,
            },
            ShareInfo {
                name: "private".to_string(),
                comment: "".to_string(),
                share_type: 0,
                encrypt_data: true,
            },
            ShareInfo {
                name: "IPC$".to_string(),
                comment: "".to_string(),
                share_type: 0x80000003,
                encrypt_data: false,
            },
        ]
    }

    #[test]
    fn ndr_writer_alignment() {
        let mut w = NdrWriter::new();
        w.write_u8(0x01);
        w.write_u32(0x12345678);
        // After u8 (pos 1), align to 4 → pos 4, then 4 bytes → pos 8.
        assert_eq!(w.buf.len(), 8);
        assert_eq!(&w.buf[4..8], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn ndr_writer_wstr() {
        let mut w = NdrWriter::new();
        w.write_wstr_conformant("AB");
        // max_count(4) + offset(4) + actual(4) + 'A'(2) + 'B'(2) + NUL(2) + pad(2) = 20
        assert_eq!(w.buf.len(), 20);
    }

    #[test]
    fn share_enum_level1_encodes_without_panic() {
        let shares = test_shares();
        let data = encode_netr_share_enum_response(&shares, 1);
        assert!(!data.is_empty());
    }

    #[test]
    fn share_enum_level1_3_shares_has_count() {
        let shares = test_shares();
        let data = encode_netr_share_enum_response(&shares, 1);
        // The count (u32) should be 3. Find it in the output.
        let count_bytes = 3u32.to_le_bytes();
        assert!(data.windows(4).any(|w| w == count_bytes));
    }

    #[test]
    fn share_get_info_found() {
        let shares = test_shares();
        let share = shares.iter().find(|s| s.name == "public").unwrap();
        let data = encode_netr_share_get_info_response(Some(share), 1);
        assert!(!data.is_empty());
        // Should contain WERR_SUCCESS (0) at the end.
        let werr = u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]);
        assert_eq!(werr, WERR_SUCCESS);
    }

    #[test]
    fn share_get_info_not_found() {
        let data = encode_netr_share_get_info_response(None, 1);
        // Should contain WERR_NERR_NETNAMENOTFOUND (2310).
        let werr = u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]);
        assert_eq!(werr, WERR_NERR_NETNAMENOTFOUND);
    }

    #[test]
    fn server_get_info_level100() {
        let data = encode_netr_server_get_info_response("rssmb", 100);
        assert!(!data.is_empty());
        // WERR_SUCCESS at the end.
        let werr = u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]);
        assert_eq!(werr, WERR_SUCCESS);
    }

    #[test]
    fn server_get_info_unsupported_level() {
        let data = encode_netr_server_get_info_response("rssmb", 999);
        let werr = u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]);
        assert_eq!(werr, WERR_INVALID_LEVEL);
    }

    #[test]
    fn parse_enum_request_level() {
        // Build a minimal NetrShareEnum request stub for level 1.
        let mut w = NdrWriter::new();
        // ServerName: unique ptr (1) + conformant wstr "\\rssmb\0"
        w.write_unique_ptr(true);
        w.write_wstr_conformant("\\rssmb");
        // Level (u32)
        w.write_u32(1);
        // Union pointer (u32)
        w.write_u32(1);
        // PreferedMaximumLength (u32)
        w.write_u32(0xFFFFFFFF);
        // ResumeHandle: unique pointer (0 = NULL)
        w.write_u32(0);

        let (level, pref) = parse_netr_share_enum_request(&w.into_vec()).unwrap();
        assert_eq!(level, 1);
        assert_eq!(pref, 0xFFFFFFFF);
    }

    #[test]
    fn parse_get_info_request() {
        // Build a minimal NetrShareGetInfo request stub.
        let mut w = NdrWriter::new();
        // ServerName: unique ptr + conformant wstr
        w.write_unique_ptr(true);
        w.write_wstr_conformant("\\rssmb");
        // NetName: reference ptr (always 1) + conformant wstr "public\0"
        w.write_u32(1); // reference pointer
        w.write_wstr_conformant("public");
        // Level (u32)
        w.write_u32(1);

        let (level, name) = parse_netr_share_get_info_request(&w.into_vec()).unwrap();
        assert_eq!(level, 1);
        assert_eq!(name, "public");
    }

    #[test]
    fn parse_server_get_info_request() {
        let mut w = NdrWriter::new();
        w.write_unique_ptr(true);
        w.write_wstr_conformant("\\rssmb");
        w.write_u32(100);
        let level = parse_netr_server_get_info_request(&w.into_vec()).unwrap();
        assert_eq!(level, 100);
    }

    // --- Golden-byte fixture: NetrShareEnum (opnum 15, level 1) ---

    #[test]
    fn netr_share_enum_golden_bytes_single_share() {
        let shares = vec![
            ShareInfo {
                name: "public".to_string(),
                comment: "Public".to_string(),
                share_type: 0,
                encrypt_data: false,
            },
        ];
        let data = encode_netr_share_enum_response(&shares, 1);

        // Walk the NDR structure:
        // Level (u32) = 1
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 1);
        // Union tag (u32) = 1
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1);
        // Container pointer (u32) = 1 (non-null)
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 1);
        // EntriesRead (u32) = 1
        assert_eq!(u32::from_le_bytes(data[12..16].try_into().unwrap()), 1);
        // BufferPtr (u32) = 1 (non-null)
        assert_eq!(u32::from_le_bytes(data[16..20].try_into().unwrap()), 1);
        // MaxCount (u32) = 1
        assert_eq!(u32::from_le_bytes(data[20..24].try_into().unwrap()), 1);

        // TotalEntries (u32) = 1 — find it after the deferred data.
        // WERROR (u32) = 0 — last 4 bytes.
        let werr = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
        assert_eq!(werr, WERR_SUCCESS);
    }

    #[test]
    fn netr_share_enum_golden_bytes_empty_shares() {
        let data = encode_netr_share_enum_response(&[], 1);
        // Level = 1, tag = 1, container_ptr = 0 (null), TotalEntries = 0, ResumePtr = 0, WERROR = 0
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 1); // Level
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1); // Tag
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 0); // ContainerPtr = null
        // TotalEntries
        assert_eq!(u32::from_le_bytes(data[12..16].try_into().unwrap()), 0);
        // ResumeHandlePtr = 0
        assert_eq!(u32::from_le_bytes(data[16..20].try_into().unwrap()), 0);
        // WERROR = 0
        assert_eq!(u32::from_le_bytes(data[20..24].try_into().unwrap()), WERR_SUCCESS);
        assert_eq!(data.len(), 24);
    }

    #[test]
    fn netr_share_enum_roundtrip_encode_decode() {
        let shares = test_shares(); // 3 shares
        let data = encode_netr_share_enum_response(&shares, 1);

        // Decode the response by walking the NDR structure:
        // Level + tag + container_ptr + entries_read + buffer_ptr + max_count
        // Then per share: netname_ptr + type + remark_ptr
        // Then deferred netname strings, deferred remark strings
        // Then total_entries + resume_ptr + werror

        let mut r = NdrReader::new(&data);
        let level = r.read_u32().unwrap();
        assert_eq!(level, 1);
        let _tag = r.read_u32().unwrap();
        let container_present = r.read_unique_ptr().unwrap();
        assert!(container_present);
        let entries_read = r.read_u32().unwrap();
        assert_eq!(entries_read, 3);
        let buffer_present = r.read_unique_ptr().unwrap();
        assert!(buffer_present);
        let max_count = r.read_u32().unwrap();
        assert_eq!(max_count, 3);

        // Read 3 SHARE_INFO_1 fixed parts
        // Share 0: "public" with comment "Public share" → remark non-null
        // Share 1: "private" with empty comment → remark null
        // Share 2: "IPC$" with empty comment → remark null, type 0x80000003
        for i in 0..3 {
            let netname_ptr = r.read_unique_ptr().unwrap();
            assert!(netname_ptr);
            let share_type = r.read_u32().unwrap();
            let remark_ptr = r.read_unique_ptr().unwrap();
            if i == 0 {
                assert!(remark_ptr, "share 0 should have non-null remark");
                assert_eq!(share_type, 0);
            } else if i == 1 {
                assert!(!remark_ptr, "share 1 should have null remark");
                assert_eq!(share_type, 0);
            } else {
                assert!(!remark_ptr, "share 2 should have null remark");
                assert_eq!(share_type, 0x80000003);
            }
        }

        // Skip deferred netname strings (3 shares)
        for _ in 0..3 {
            r.skip_wstr_conformant().unwrap();
        }
        // Skip deferred remark strings (only share 0 has a remark)
        r.skip_wstr_conformant().unwrap();

        // TotalEntries + ResumeHandle + WERROR
        let total_entries = r.read_u32().unwrap();
        assert_eq!(total_entries, 3);
        let _resume = r.read_unique_ptr().unwrap();
        let werr = r.read_u32().unwrap();
        assert_eq!(werr, WERR_SUCCESS);
    }

    // --- Golden-byte fixture: NetrShareGetInfo (opnum 16, level 1) ---

    #[test]
    fn netr_share_get_info_golden_bytes_found() {
        let share = ShareInfo {
            name: "public".to_string(),
            comment: "Public share".to_string(),
            share_type: 0,
            encrypt_data: false,
        };
        let data = encode_netr_share_get_info_response(Some(&share), 1);
        // Level + tag + union_ptr(non-null) + netname_ptr(non-null) + type + remark_ptr(non-null)
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 1); // Level
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1); // Tag
        assert_ne!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 0); // UnionPtr
        // WERROR at the end
        let werr = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
        assert_eq!(werr, WERR_SUCCESS);
    }

    #[test]
    fn netr_share_get_info_golden_bytes_not_found() {
        let data = encode_netr_share_get_info_response(None, 1);
        // Level + tag + null_ptr + WERROR
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 0); // null union ptr
        let werr = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(werr, WERR_NERR_NETNAMENOTFOUND);
    }

    // --- Golden-byte fixture: NetrServerGetInfo (opnum 21, level 100) ---

    #[test]
    fn netr_server_get_info_golden_bytes_level100() {
        let data = encode_netr_server_get_info_response("rssmb", 100);
        // UnionPtr (u32, non-null) + Level (u32=100) + PlatformId (u32=500) +
        // NamePtr (u32, non-null) + conformant wstr "rssmb\0" + WERROR (u32=0)
        let union_ptr = u32::from_le_bytes(data[0..4].try_into().unwrap());
        assert_ne!(union_ptr, 0);
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 100); // Level
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 500); // PlatformId
        let name_ptr = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_ne!(name_ptr, 0);
        // WERROR at end
        let werr = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
        assert_eq!(werr, WERR_SUCCESS);
    }
}