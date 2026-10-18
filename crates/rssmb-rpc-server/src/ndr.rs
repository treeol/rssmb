//! NDR20 (Network Data Representation) encoder/decoder for SrvSvc.
//!
//! Hand-written for the specific structures needed by Step 8:
//! NetrShareEnum (opnum 15), NetrShareGetInfo (16), NetrServerGetInfo (21).
//! Only little-endian NDR20 is supported.

use super::ShareInfo;

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

/// First referent ID handed out for a non-NULL unique pointer. Matches
/// Samba/Windows (0x00020000, then +4 per pointer), which keeps encoded
/// stubs byte-stable and comparable with reference captures.
pub const FIRST_REFERENT_ID: u32 = 0x0002_0000;

/// NDR20 encoder. Writes little-endian primitives with alignment.
pub struct NdrWriter {
    buf: Vec<u8>,
    next_referent: u32,
}

impl NdrWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            next_referent: FIRST_REFERENT_ID,
        }
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
    /// a u32 referent ID where 0 = NULL. Non-NULL pointers get distinct,
    /// increasing IDs (0x00020000, 0x00020004, ...). The referent data is
    /// written by the caller where NDR defers it.
    pub fn write_unique_ptr(&mut self, is_present: bool) -> u32 {
        let ptr = if is_present {
            let id = self.next_referent;
            self.next_referent = self.next_referent.wrapping_add(4);
            id
        } else {
            0
        };
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

impl Default for NdrWriter {
    fn default() -> Self {
        Self::new()
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

/// SHARE_INFO_1 fixed part: {netname ptr, type (u32), remark ptr}.
///
/// The remark pointer is always non-NULL; an empty comment is sent as the
/// empty string (max_count = actual_count = 1, just the NUL), as Samba and
/// Windows do. Some clients (go-smb2 before 2026-09, i.e. rclone <= 1.75)
/// assume every entry carries both strings.
fn encode_share_info_1_fixed(w: &mut NdrWriter, share: &ShareInfo) {
    w.write_unique_ptr(true); // shi1_netname
    w.write_u32(share.share_type); // shi1_type
    w.write_unique_ptr(true); // shi1_remark
}

/// SHARE_INFO_1 deferred pointees, in the order their pointers appear in
/// the fixed part: netname, then remark.
fn encode_share_info_1_deferred(w: &mut NdrWriter, share: &ShareInfo) {
    w.write_wstr_conformant(&share.name);
    w.write_wstr_conformant(&share.comment);
}

/// SHARE_INFO_1 structure: {netname (wstr), type (u32), remark (wstr)}
pub fn encode_share_info_1(w: &mut NdrWriter, share: &ShareInfo) {
    encode_share_info_1_fixed(w, share);
    encode_share_info_1_deferred(w, share);
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
///     RemarkPtr (u32) = nonzero (unique; empty comment = "")
///   Deferred strings, per element in array order (C706 §14.3.12.3):
///     netname[0], remark[0], netname[1], remark[1], ...
/// TotalEntries (u32) = N
/// ResumeHandlePtr (u32) = 0 (null)
/// WERROR (u32) = 0
/// ```
///
/// Referent IDs come from [`NdrWriter`]'s counter (0x00020000, +4), so the
/// output is byte-for-byte the Samba layout for the same shares.
pub fn encode_netr_share_enum_response(shares: &[ShareInfo], level: u32) -> Vec<u8> {
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
            // N × SHARE_INFO_1 fixed parts, then each element's deferred
            // strings in element order (netname[i], remark[i]).
            for share in shares.iter() {
                encode_share_info_1_fixed(&mut w, share);
            }
            for share in shares.iter() {
                encode_share_info_1_deferred(&mut w, share);
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
pub fn encode_netr_share_get_info_response(share: Option<&ShareInfo>, level: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();

    // MS-SRVS 3.1.4.10: [out, switch_is(Level)] LPSHARE_INFO InfoStruct.
    // A non-encapsulated union parameter is marshalled as its discriminant
    // followed by the arm — here a unique pointer to SHARE_INFO_1. There is
    // no separate Level field in the reply (unlike SHARE_ENUM_STRUCT).
    if let Some(s) = share {
        w.write_u32(level); // union discriminant
        let info_ptr = w.write_unique_ptr(true); // arm: LPSHARE_INFO_1
        if info_ptr != 0 {
            // SHARE_INFO_1: fixed part, then netname and remark (always
            // present; empty comment = "").
            encode_share_info_1(&mut w, s);
        }
        // WERROR
        w.write_u32(WERR_SUCCESS);
    } else {
        // No share found — discriminant + NULL arm pointer.
        w.write_u32(level);
        w.write_unique_ptr(false);
        w.write_u32(WERR_NERR_NETNAMENOTFOUND);
    }

    w.into_vec()
}

/// Encode a NetrServerGetInfo response (opnum 21, level 100).
/// SERVER_INFO_100: {sv100_platform_id (u32), sv100_name (wstr)}
pub fn encode_netr_server_get_info_response(server_name: &str, level: u32) -> Vec<u8> {
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
    // NetName: `[in, string] WCHAR*` — a top-level [ref] pointer, which has
    // no wire representation (C706 §14.3.11.1): the conformant varying
    // string (max_count, offset, actual_count, chars) follows directly.
    r.align(4);
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
        // Exact stubs sent by impacket's NetrShareGetInfo (hNetrShareGetInfo)
        // for NetName "public", Level 1. NetName is a top-level [ref]
        // pointer, so it has no referent ID on the wire — the conformant
        // string follows ServerName directly (C706 §14.3.11.1).
        #[rustfmt::skip]
        let null_server: &[u8] = &[
            0x00, 0x00, 0x00, 0x00,                         // ServerName: NULL
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max=7 off=0
            0x07, 0x00, 0x00, 0x00,                         // actual=7
            b'p', 0, b'u', 0, b'b', 0, b'l', 0, b'i', 0, b'c', 0, 0, 0,
            0xbf, 0xbf,                                     // pad to 4
            0x01, 0x00, 0x00, 0x00,                         // Level
        ];
        assert_eq!(
            parse_netr_share_get_info_request(null_server),
            Some((1, "public".to_string()))
        );

        #[rustfmt::skip]
        let empty_server: &[u8] = &[
            0xd8, 0x0d, 0x00, 0x00,                         // ServerName: referent
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max=1 off=0
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00,             // actual=1, "\0"
            0xab, 0xab,                                     // pad to 4
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NetName max=7 off=0
            0x07, 0x00, 0x00, 0x00,                         // actual=7
            b'p', 0, b'u', 0, b'b', 0, b'l', 0, b'i', 0, b'c', 0, 0, 0,
            0xbf, 0xbf,
            0x01, 0x00, 0x00, 0x00,                         // Level
        ];
        assert_eq!(
            parse_netr_share_get_info_request(empty_server),
            Some((1, "public".to_string()))
        );
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
        let shares = vec![ShareInfo {
            name: "public".to_string(),
            comment: "Public".to_string(),
            share_type: 0,
            encrypt_data: false,
        }];
        let data = encode_netr_share_enum_response(&shares, 1);

        // Walk the NDR structure:
        // Level (u32) = 1
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 1);
        // Union tag (u32) = 1
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1);
        // Container pointer (u32) = first referent ID
        assert_eq!(
            u32::from_le_bytes(data[8..12].try_into().unwrap()),
            FIRST_REFERENT_ID
        );
        // EntriesRead (u32) = 1
        assert_eq!(u32::from_le_bytes(data[12..16].try_into().unwrap()), 1);
        // BufferPtr (u32) = next referent ID
        assert_eq!(
            u32::from_le_bytes(data[16..20].try_into().unwrap()),
            FIRST_REFERENT_ID + 4
        );
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
        assert_eq!(
            u32::from_le_bytes(data[20..24].try_into().unwrap()),
            WERR_SUCCESS
        );
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

        // Read 3 SHARE_INFO_1 fixed parts. Every share has a non-null
        // remark pointer, including the ones with an empty comment.
        for i in 0..3 {
            let netname_ptr = r.read_unique_ptr().unwrap();
            assert!(netname_ptr);
            let share_type = r.read_u32().unwrap();
            let remark_ptr = r.read_unique_ptr().unwrap();
            assert!(remark_ptr, "share {i} must have a non-null remark pointer");
            let expected_type = if i == 2 { 0x80000003 } else { 0 };
            assert_eq!(share_type, expected_type);
        }

        // Deferred strings: netname[i], remark[i] per element.
        for _ in 0..3 {
            r.skip_wstr_conformant().unwrap(); // netname
            r.skip_wstr_conformant().unwrap(); // remark ("" when empty)
        }

        // TotalEntries + ResumeHandle + WERROR
        let total_entries = r.read_u32().unwrap();
        assert_eq!(total_entries, 3);
        let _resume = r.read_unique_ptr().unwrap();
        let werr = r.read_u32().unwrap();
        assert_eq!(werr, WERR_SUCCESS);
    }

    /// Decode a level-1 NetrShareEnum stub with a strict NDR walker:
    /// referent IDs must be non-zero and unique, and every non-NULL
    /// pointer's string must appear in element order. Returns
    /// (name, type, remark) triples.
    fn decode_share_enum_strict(data: &[u8]) -> Vec<(String, u32, Option<String>)> {
        fn read_wstr(r: &mut NdrReader) -> String {
            let max = r.read_u32().unwrap();
            let off = r.read_u32().unwrap();
            let actual = r.read_u32().unwrap();
            assert_eq!(off, 0);
            assert_eq!(max, actual, "max_count must equal actual_count");
            let mut u = Vec::new();
            for _ in 0..actual {
                u.push(r.read_u16().unwrap());
            }
            assert_eq!(u.pop(), Some(0), "string must be NUL-terminated");
            r.align(4);
            String::from_utf16(&u).unwrap()
        }
        let mut ids = std::collections::HashSet::new();
        let mut uniq = |id: u32| {
            if id != 0 {
                assert!(ids.insert(id), "referent ID 0x{id:08x} reused");
            }
            id != 0
        };
        let mut r = NdrReader::new(data);
        assert_eq!(r.read_u32().unwrap(), 1); // Level
        assert_eq!(r.read_u32().unwrap(), 1); // union switch
        assert!(uniq(r.read_u32().unwrap())); // container
        let n = r.read_u32().unwrap() as usize;
        assert!(uniq(r.read_u32().unwrap())); // array
        assert_eq!(r.read_u32().unwrap() as usize, n); // max_count
        let mut fixed = Vec::new();
        for _ in 0..n {
            let np = uniq(r.read_u32().unwrap());
            let ty = r.read_u32().unwrap();
            let rp = uniq(r.read_u32().unwrap());
            fixed.push((np, ty, rp));
        }
        let mut out = Vec::new();
        for (np, ty, rp) in fixed {
            assert!(np, "netname pointer must be non-null");
            let name = read_wstr(&mut r);
            let remark = rp.then(|| read_wstr(&mut r));
            out.push((name, ty, remark));
        }
        assert_eq!(r.read_u32().unwrap() as usize, n); // TotalEntries
        assert_eq!(r.read_u32().unwrap(), 0); // ResumeHandle (null)
        assert_eq!(r.read_u32().unwrap(), WERR_SUCCESS);
        assert_eq!(r.remaining(), 0, "trailing bytes");
        out
    }

    /// The 3-share / 2-comment case, against Samba 4.17.12's NetrShareEnum
    /// (level 1) reply for shares public "Pub", private "Priv", IPC$ "".
    ///
    /// Captured with impacket against `smbd` and normalized in two places
    /// that are not encoding rules but server choices:
    /// - Samba's referent counter for this call starts at 0x00020010
    ///   (it numbers request-side pointers first); shifted by -0x10 to
    ///   rssmb's 0x00020000 start. Step (+4) and order are Samba's.
    /// - Samba's IPC$ remark is its `server string`; replaced by "" and
    ///   the trailing ResumeHandle by NULL (impacket passed a non-NULL
    ///   resume handle, which Samba echoes; rssmb always returns NULL).
    #[test]
    fn netr_share_enum_matches_samba_layout_3_shares_2_comments() {
        #[rustfmt::skip]
        let samba: &[&str] = &[
            "01 00 00 00 01 00 00 00 00 00 02 00 03 00 00 00",
            "04 00 02 00 03 00 00 00 08 00 02 00 00 00 00 00",
            "0c 00 02 00 10 00 02 00 00 00 00 00 14 00 02 00",
            "18 00 02 00 03 00 00 80 1c 00 02 00 07 00 00 00",
            "00 00 00 00 07 00 00 00 70 00 75 00 62 00 6c 00",
            "69 00 63 00 00 00 00 00 04 00 00 00 00 00 00 00",
            "04 00 00 00 50 00 75 00 62 00 00 00 08 00 00 00",
            "00 00 00 00 08 00 00 00 70 00 72 00 69 00 76 00",
            "61 00 74 00 65 00 00 00 05 00 00 00 00 00 00 00",
            "05 00 00 00 50 00 72 00 69 00 76 00 00 00 00 00",
            "05 00 00 00 00 00 00 00 05 00 00 00 49 00 50 00",
            "43 00 24 00 00 00 00 00 01 00 00 00 00 00 00 00",
            "01 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00",
            "00 00 00 00",
        ];
        let expected: Vec<u8> = samba
            .iter()
            .flat_map(|l| l.split_whitespace())
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        let shares = vec![
            ShareInfo {
                name: "public".into(),
                comment: "Pub".into(),
                share_type: STYPE_DISKTREE,
                encrypt_data: false,
            },
            ShareInfo {
                name: "private".into(),
                comment: "Priv".into(),
                share_type: STYPE_DISKTREE,
                encrypt_data: false,
            },
            ShareInfo {
                name: "IPC$".into(),
                comment: String::new(),
                share_type: STYPE_IPC_SPECIAL,
                encrypt_data: false,
            },
        ];
        let data = encode_netr_share_enum_response(&shares, 1);
        assert_eq!(data, expected);

        // And the pairing survives a strict decode.
        assert_eq!(
            decode_share_enum_strict(&data),
            vec![
                ("public".into(), 0, Some("Pub".into())),
                ("private".into(), 0, Some("Priv".into())),
                ("IPC$".into(), STYPE_IPC_SPECIAL, Some(String::new())),
            ]
        );
    }

    #[test]
    fn netr_share_enum_empty_comment_is_empty_string_not_null() {
        let data = encode_netr_share_enum_response(&test_shares(), 1);
        let decoded = decode_share_enum_strict(&data);
        assert_eq!(decoded[0].2.as_deref(), Some("Public share"));
        assert_eq!(decoded[1].2.as_deref(), Some(""));
        assert_eq!(decoded[2].2.as_deref(), Some(""));
    }

    #[test]
    fn ndr_writer_referent_ids_are_distinct_and_increasing() {
        let mut w = NdrWriter::new();
        assert_eq!(w.write_unique_ptr(true), 0x0002_0000);
        assert_eq!(w.write_unique_ptr(false), 0);
        assert_eq!(w.write_unique_ptr(true), 0x0002_0004);
        assert_eq!(w.write_unique_ptr(true), 0x0002_0008);
    }

    /// NetrShareGetInfo level 1 reply, against Samba 4.17.12 for public
    /// "Pub": discriminant + LPSHARE_INFO_1 arm + WERROR (MS-SRVS 3.1.4.10),
    /// no separate Level field. Samba's referent IDs (0x00020004, +4) are
    /// shifted to rssmb's 0x00020000 start; nothing else is normalized.
    #[test]
    fn netr_share_get_info_matches_samba_layout() {
        #[rustfmt::skip]
        let expected: Vec<u8> = [
            "01 00 00 00 00 00 02 00 04 00 02 00 00 00 00 00",
            "08 00 02 00 07 00 00 00 00 00 00 00 07 00 00 00",
            "70 00 75 00 62 00 6c 00 69 00 63 00 00 00 00 00",
            "04 00 00 00 00 00 00 00 04 00 00 00 50 00 75 00",
            "62 00 00 00 00 00 00 00",
        ]
        .iter()
        .flat_map(|l| l.split_whitespace())
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
        let share = ShareInfo {
            name: "public".into(),
            comment: "Pub".into(),
            share_type: STYPE_DISKTREE,
            encrypt_data: false,
        };
        let data = encode_netr_share_get_info_response(Some(&share), 1);
        assert_eq!(data, expected);
    }

    #[test]
    fn netr_share_get_info_empty_comment_is_empty_string() {
        let share = ShareInfo {
            name: "IPC$".into(),
            comment: String::new(),
            share_type: STYPE_IPC_SPECIAL,
            encrypt_data: false,
        };
        let data = encode_netr_share_get_info_response(Some(&share), 1);
        let mut r = NdrReader::new(&data);
        assert_eq!(r.read_u32().unwrap(), 1); // discriminant
        assert!(r.read_unique_ptr().unwrap()); // info
        assert!(r.read_unique_ptr().unwrap()); // netname
        assert_eq!(r.read_u32().unwrap(), STYPE_IPC_SPECIAL);
        assert!(r.read_unique_ptr().unwrap(), "remark must be non-null");
        r.skip_wstr_conformant().unwrap(); // "IPC$"
        assert_eq!(r.read_u32().unwrap(), 1); // remark max_count (just NUL)
        assert_eq!(r.read_u32().unwrap(), 0); // offset
        assert_eq!(r.read_u32().unwrap(), 1); // actual_count
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
        // Discriminant + arm ptr(non-null) + netname_ptr + type + remark_ptr
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), 1); // discriminant
        assert_eq!(
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            FIRST_REFERENT_ID
        ); // arm ptr
        assert_eq!(
            u32::from_le_bytes(data[8..12].try_into().unwrap()),
            FIRST_REFERENT_ID + 4
        ); // shi1_netname ptr
        assert_eq!(u32::from_le_bytes(data[12..16].try_into().unwrap()), 0); // shi1_type
        let werr = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
        assert_eq!(werr, WERR_SUCCESS);
    }

    #[test]
    fn netr_share_get_info_golden_bytes_not_found() {
        let data = encode_netr_share_get_info_response(None, 1);
        // Discriminant + NULL arm pointer + WERROR — exactly 12 bytes.
        assert_eq!(
            data,
            [
                1u32.to_le_bytes(),
                0u32.to_le_bytes(),
                WERR_NERR_NETNAMENOTFOUND.to_le_bytes()
            ]
            .concat()
        );
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
