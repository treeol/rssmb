//! Basic wire types: Guid, FileTime, Boolean, PosMarker, SizedWideString.
//!
//! These are leaf types with no SMB message dependencies. They match the
//! wire layout of the equivalent types in smb-dtyp, which we used as a
//! reference. See MS-DTYP §2.3 for Guid/FileTime and MS-FSCC §2.1.8 for
//! Boolean.

use std::io::{Read, Seek, Write};

use binrw::{Endian, prelude::*};

// ── Guid ────────────────────────────────────────────────────────────
// MS-DTYP §2.3.4: 16-byte GUID, little-endian (u32, u16, u16, [u8;8]).

/// A 16-byte GUID, wire-encoded little-endian.
#[derive(BinRead, BinWrite, Clone, Copy, PartialEq, Eq, Default)]
#[brw(little)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

impl Guid {
    pub const SIZE: usize = 16;
    pub const ZERO: Guid = Guid(0, 0, 0, [0; 8]);
    pub const MAX: Guid = Guid(u32::MAX, u16::MAX, u16::MAX, [u8::MAX; 8]);

    /// Parse a UUID string (with or without braces) into a Guid.
    ///
    /// The string format is `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    /// The first three fields are big-endian, the last two are raw bytes.
    pub const fn parse_uuid(s: &str) -> Result<Guid, &'static str> {
        let b = s.as_bytes();
        let so = if b[0] == b'{' && b[b.len() - 1] == b'}' {
            if s.len() != 38 {
                return Err("Invalid UUID format");
            }
            1
        } else {
            if s.len() != 36 {
                return Err("Invalid UUID format");
            }
            0
        };
        if b[so + 8] != b'-' || b[so + 13] != b'-' || b[so + 18] != b'-' || b[so + 23] != b'-' {
            return Err("Invalid UUID format");
        }

        macro_rules! pb {
            ($b:expr, $i:expr) => {
                match parse_hex_byte($b, $i) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                }
            };
        }

        Ok(Guid(
            u32::from_be_bytes([pb!(b, so), pb!(b, so + 2), pb!(b, so + 4), pb!(b, so + 6)]),
            u16::from_be_bytes([pb!(b, so + 9), pb!(b, so + 11)]),
            u16::from_be_bytes([pb!(b, so + 14), pb!(b, so + 16)]),
            [
                pb!(b, so + 19), pb!(b, so + 21),
                pb!(b, so + 24), pb!(b, so + 26),
                pb!(b, so + 28), pb!(b, so + 30),
                pb!(b, so + 32), pb!(b, so + 34),
            ],
        ))
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self::try_from(&bytes).unwrap()
    }
}

/// Parse a single hex nibble.
const fn hex_val(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("Invalid hex digit"),
    }
}

/// Parse a hex byte pair at `b[i]`, `b[i+1]`.
const fn parse_hex_byte(b: &[u8], i: usize) -> Result<u8, &'static str> {
    let hi = match hex_val(b[i]) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let lo = match hex_val(b[i + 1]) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok((hi << 4) | lo)
}

/// Compile-time Guid construction from a UUID string.
#[macro_export]
macro_rules! make_guid {
    ($s:expr) => {{
        match $crate::Guid::parse_uuid($s) {
            Ok(g) => g,
            Err(_) => panic!("Invalid GUID format"),
        }
    }};
}

impl From<[u8; 16]> for Guid {
    fn from(value: [u8; 16]) -> Self {
        Self::try_from(&value).unwrap()
    }
}

impl TryFrom<&[u8; 16]> for Guid {
    type Error = binrw::Error;

    fn try_from(value: &[u8; 16]) -> Result<Self, Self::Error> {
        use std::io::Cursor;
        let mut cursor = Cursor::new(value);
        Guid::read(&mut cursor)
    }
}

impl From<Guid> for [u8; 16] {
    fn from(val: Guid) -> Self {
        use std::io::Cursor;
        let mut cursor = Cursor::new(Vec::new());
        val.write(&mut cursor).unwrap();
        cursor.into_inner().try_into().unwrap()
    }
}

impl std::str::FromStr for Guid {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Guid::parse_uuid(s)
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:012x}",
            self.0, self.1, self.2, self.3[0], self.3[1],
            self.3[2..].iter().fold(0u64, |acc, &x| (acc << 8) + x as u64)
        )
    }
}

impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

// ── FileTime ────────────────────────────────────────────────────────
// MS-DTYP §2.3.3: 100-nanosecond intervals since 1601-01-01 UTC, u64 LE.

/// A FILETIME value — 100-nanosecond intervals since 1601-01-01 UTC.
#[derive(BinRead, BinWrite, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[brw(little)]
pub struct FileTime {
    value: u64,
}

impl FileTime {
    pub const ZERO: FileTime = FileTime { value: 0 };

    /// 100-nanosecond intervals since the FILETIME epoch (1601-01-01 UTC).
    pub const FILETIME_EPOCH_OFFSET: u64 = 116_444_736_000_000_000;

    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    pub fn as_u64(&self) -> u64 {
        self.value
    }
}

impl From<u64> for FileTime {
    fn from(value: u64) -> Self {
        Self { value }
    }
}

impl From<FileTime> for u64 {
    fn from(ft: FileTime) -> Self {
        ft.value
    }
}

impl std::ops::Deref for FileTime {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

// ── Boolean ─────────────────────────────────────────────────────────
// MS-FSCC §2.1.8: 1-byte BOOL, non-zero = true.

/// A 1-byte Boolean (WinAPI BOOL). Non-zero is true, zero is false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Boolean(bool);

impl Boolean {
    const _VALIDATE_SIZE_OF: [u8; 1] = [0; std::mem::size_of::<Self>()];
}

impl BinRead for Boolean {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let v: u8 = u8::read_options(reader, Endian::Little, ())?;
        Ok(Boolean(v != 0))
    }
}

impl BinWrite for Boolean {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let v: u8 = if self.0 { 1 } else { 0 };
        v.write_options(writer, Endian::Little, ())
    }
}

impl From<bool> for Boolean {
    fn from(value: bool) -> Self {
        Boolean(value)
    }
}

impl From<Boolean> for bool {
    fn from(val: Boolean) -> Self {
        val.0
    }
}

// ReadEndian/WriteEndian so that `read_le`/`write_le` work on structs
// that contain Boolean fields.
impl binrw::meta::ReadEndian for Boolean {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::Endian(Endian::Little);
}
impl binrw::meta::WriteEndian for Boolean {
    const ENDIAN: binrw::meta::EndianKind = binrw::meta::EndianKind::Endian(Endian::Little);
}

// ── PosMarker ───────────────────────────────────────────────────────
// Stores the stream position where a value was read, for relative
// offset/length backpatching in variable-length messages.
//
// Source: smb-dtyp binrw_util/pos_marker.rs (MIT). We own this copy.

use binrw::io::{Read as _, Seek as _, Write as _};

/// Wraps a value and records the stream position where it was read.
///
/// Used for offset fields that are relative to the start of the message.
/// On write, a placeholder is written and backpatched with the actual
/// offset of the associated data.
#[derive(Default, PartialEq, Eq)]
pub struct PosMarker<T> {
    pub pos: std::sync::OnceLock<u64>,
    pub value: T,
}

impl<T> PosMarker<T> {
    /// Create a new PosMarker with the given value.
    pub fn new(value: T) -> Self {
        Self {
            pos: std::sync::OnceLock::new(),
            value,
        }
    }

    /// Returns a [SeekFrom] that seeks relative from the position of the PosMarker.
    #[inline]
    pub fn seek_from(&self, offset: u64) -> std::io::SeekFrom {
        self.seek_from_if(offset, true)
    }

    /// Returns a [SeekFrom] that seeks relative from the position of the PosMarker if condition is true.
    pub fn seek_from_if(&self, offset: u64, condition: bool) -> std::io::SeekFrom {
        if condition {
            std::io::SeekFrom::Start(self.pos.get().unwrap() + offset)
        } else {
            std::io::SeekFrom::Current(0)
        }
    }

    fn get_pos(&self) -> binrw::BinResult<u64> {
        let value = self.pos.get().ok_or(binrw::error::Error::Custom {
            pos: 0,
            err: Box::new("PosMarker has not been written to yet"),
        })?;
        Ok(*value)
    }
}

impl<T> PosMarker<T>
where
    T: Into<u64> + Copy,
{
    /// Returns a SeekFrom to the position described by the PosMarker.
    pub fn try_seek_relative(&self, zero_check: bool) -> binrw::BinResult<std::io::SeekFrom> {
        let pos = std::io::SeekFrom::Start(self.get_pos()? + self.value.into());
        Ok(if !zero_check || Into::<u64>::into(self.value) > 0 {
            pos
        } else {
            std::io::SeekFrom::Current(0)
        })
    }

    /// Like [try_seek_relative](Self::try_seek_relative), but unwraps the result.
    pub fn seek_relative(&self, zero_check: bool) -> std::io::SeekFrom {
        self.try_seek_relative(zero_check).unwrap()
    }
}

impl<T: BinRead> BinRead for PosMarker<T> {
    type Args<'a> = T::Args<'a>;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let pos = reader.stream_position()?;
        T::read_options(reader, endian, args).map(|value| Self {
            pos: std::sync::OnceLock::from(pos),
            value,
        })
    }
}

impl<T: BinWrite<Args<'static> = ()> + Default> BinWrite for PosMarker<T> {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        self.pos
            .set(writer.stream_position()?)
            .map_err(|_| binrw::error::Error::Custom {
                pos: writer.stream_position().unwrap(),
                err: Box::new("PosMarker has already been written to"),
            })?;
        T::default().write_options(writer, endian, ())
    }
}

impl<T> PosMarker<T>
where
    T: BinWrite<Args<'static> = ()> + TryFrom<u64>,
    T::Error: binrw::error::CustomError + 'static,
{
    const NO_EXTRA_SIZE: u64 = 0;
    const NO_EXTRA_OFFSET: u64 = 0;

    /// Move back the writer, update the written value and return to the end.
    pub fn write_back<V, W>(&self, value: V, writer: &mut W, endian: Endian) -> binrw::BinResult<()>
    where
        V: TryInto<T> + std::fmt::Debug,
        W: Write + Seek,
    {
        let return_to = writer.stream_position()?;
        writer.seek(std::io::SeekFrom::Start(self.get_pos()?))?;
        value
            .try_into()
            .map_err(|_| binrw::error::Error::Custom {
                pos: self.get_pos().unwrap(),
                err: Box::new("Error converting value to T"),
            })?
            .write_options(writer, endian, ())?;
        writer.seek(std::io::SeekFrom::Start(return_to))?;
        Ok(())
    }

    #[inline]
    #[binrw::writer(writer, endian)]
    fn write_hero<V, S, B>(
        value: &V,
        write_size_to: Option<&Self>,
        write_offset_to: Option<&PosMarker<S>>,
        offset_relative_to: Option<&PosMarker<B>>,
        value_args: V::Args<'_>,
        size_plus: u64,
        offset_plus: u64,
    ) -> binrw::BinResult<()>
    where
        V: BinWrite,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        let start_offset = writer.stream_position()?;
        if let Some(write_offset_at) = write_offset_to {
            let base_offset_val = match offset_relative_to {
                Some(offset_base) => offset_base.get_pos()?,
                None => 0,
            };
            let offset_to_write = start_offset - base_offset_val + offset_plus;
            write_offset_at.write_back(offset_to_write, writer, endian)?;
        };
        value.write_options(writer, endian, value_args)?;
        let total_size = writer.stream_position()? - start_offset;
        if let Some(write_size_to) = write_size_to {
            write_size_to.write_back(total_size + size_plus, writer, endian)?;
        }
        Ok(())
    }

    /// Writer for value, fill absolute offset to offset location.
    #[binrw::writer(writer, endian)]
    pub fn write_aoff<U>(value: &U, write_offset_to: &Self) -> binrw::BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_size: Option<&PosMarker<T>> = None;
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (no_size, Some(write_offset_to), no_base, (), Self::NO_EXTRA_SIZE, Self::NO_EXTRA_OFFSET),
        )
    }

    /// Writer for value, fill written size to size location.
    #[binrw::writer(writer, endian)]
    pub fn write_size<U>(value: &U, write_size_to: &Self) -> binrw::BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let no_offset: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (Some(write_size_to), no_offset, no_offset, (), Self::NO_EXTRA_SIZE, Self::NO_EXTRA_OFFSET),
        )
    }

    /// Writer for value, fill absolute offset + size.
    #[binrw::writer(writer, endian)]
    pub fn write_aoff_size<U, S>(
        value: &U,
        write_offset_to: &PosMarker<S>,
        write_size_to: &Self,
    ) -> binrw::BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (Some(write_size_to), Some(write_offset_to), no_base, (), Self::NO_EXTRA_SIZE, Self::NO_EXTRA_OFFSET),
        )
    }

    /// Writer for value, fill relative offset + size.
    #[binrw::writer(writer, endian)]
    pub fn write_roff_size<U, S>(
        value: &U,
        write_offset_to: &PosMarker<S>,
        write_size_to: &Self,
    ) -> binrw::BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
        S: BinWrite<Args<'static> = ()> + TryFrom<u64>,
        S::Error: binrw::error::CustomError + 'static,
    {
        let no_base: Option<&PosMarker<T>> = None;
        Self::write_hero(
            value,
            writer,
            endian,
            (Some(write_size_to), Some(write_offset_to), no_base, (), Self::NO_EXTRA_SIZE, Self::NO_EXTRA_OFFSET),
        )
    }
}

impl<T> std::fmt::Debug for PosMarker<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PosMarker")
            .field("pos", &self.pos)
            .field("value", &self.value)
            .finish()
    }
}

impl<T> std::clone::Clone for PosMarker<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            pos: self.pos.clone(),
            value: self.value.clone(),
        }
    }
}

// ── SizedWideString ─────────────────────────────────────────────────
// A UTF-16LE string whose length is given by a separate field.
// The length is in *bytes*, not characters. Each u16 is 2 bytes.

/// Size argument for [`SizedWideString`].
#[derive(Debug, Clone, Copy)]
pub enum SizedStringSize {
    /// Length in bytes (each char is 2 bytes, so bytes must be even).
    Bytes(u32),
    /// Length in bytes, given as a u16 (common in SMB2 headers).
    Bytes16(u16),
}

/// A UTF-16LE string whose byte length is specified externally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SizedWideString {
    pub data: Vec<u16>,
}

impl SizedWideString {
    pub fn from_str(s: &str) -> Self {
        Self {
            data: s.encode_utf16().collect(),
        }
    }

    pub fn size_bytes(&self) -> u32 {
        (self.data.len() * 2) as u32
    }

    /// Alias for `size_bytes()` — the smb-rs API uses `size()`.
    pub fn size(&self) -> u32 {
        self.size_bytes()
    }
}

/// BinRead args for [`SizedWideString`].
#[derive(binrw::NamedArgs, Debug, Clone, Copy)]
pub struct SizedWideStringArgs {
    pub size: SizedStringSize,
}

impl BinRead for SizedWideString {
    type Args<'a> = SizedWideStringArgs;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _endian: Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let bytes = match args.size {
            SizedStringSize::Bytes(n) => n as usize,
            SizedStringSize::Bytes16(n) => n as usize,
        };
        let chars = bytes / 2;
        let mut data = Vec::with_capacity(chars);
        for _ in 0..chars {
            let lo: u8 = u8::read_options(reader, Endian::Little, ())?;
            let hi: u8 = u8::read_options(reader, Endian::Little, ())?;
            data.push(u16::from_le_bytes([lo, hi]));
        }
        Ok(SizedWideString { data })
    }
}

impl BinWrite for SizedWideString {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        _endian: Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        for c in &self.data {
            let bytes = c.to_le_bytes();
            bytes[0].write_options(writer, Endian::Little, ())?;
            bytes[1].write_options(writer, Endian::Little, ())?;
        }
        Ok(())
    }
}

impl From<&str> for SizedWideString {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl From<String> for SizedWideString {
    fn from(s: String) -> Self {
        Self::from_str(&s)
    }
}

impl std::fmt::Display for SizedWideString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for c in &self.data {
            if let Some(ch) = char::from_u32(*c as u32) {
                write!(f, "{}", ch)?;
            }
        }
        Ok(())
    }
}

// ── FixedWideString ──────────────────────────────────────────────

/// Fixed-size wide string (N u16 code units, always N*2 bytes on wire).
///
/// Used for 8.3 short filenames in directory enumeration (MS-FSCC §2.4).
/// The field is always exactly N characters; `ShortNameLength` tells
/// how many are meaningful, but the field itself is fixed-size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedWideString<const N: usize> {
    pub data: [u16; N],
}

impl<const N: usize> Default for FixedWideString<N> {
    fn default() -> Self {
        Self { data: [0u16; N] }
    }
}

impl<const N: usize> binrw::BinRead for FixedWideString<N> {
    type Args<'a> = ();
    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let mut data = [0u16; N];
        for item in data.iter_mut() {
            *item = u16::read_options(reader, endian, ())?;
        }
        Ok(Self { data })
    }
}

impl<const N: usize> binrw::BinWrite for FixedWideString<N> {
    type Args<'a> = ();
    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        for item in self.data.iter() {
            item.write_options(writer, endian, ())?;
        }
        Ok(())
    }
}

impl<const N: usize> FixedWideString<N> {
    pub const SIZE_BYTES: usize = N * 2;

    pub fn from_slice(slice: &[u16]) -> Self {
        let mut data = [0u16; N];
        let len = slice.len().min(N);
        data[..len].copy_from_slice(&slice[..len]);
        Self { data }
    }

    pub fn from_str(s: &str) -> Self {
        let u16s: Vec<u16> = s.encode_utf16().collect();
        Self::from_slice(&u16s)
    }
}

impl<const N: usize> std::fmt::Display for FixedWideString<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let trimmed: Vec<u16> = self.data.iter().take_while(|&&c| c != 0).copied().collect();
        write!(f, "{}", String::from_utf16_lossy(&trimmed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_guid_roundtrip() {
        let guid = Guid(0x065eadf1, 0x6daf, 0x1543, [0xb0, 0x4f, 0x10, 0xe6, 0x90, 0x84, 0xc9, 0xae]);
        let mut buf = Cursor::new(Vec::new());
        guid.write(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 16);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: Guid = Guid::read(&mut cursor).unwrap();
        assert_eq!(decoded, guid);
        assert_eq!(
            guid.to_string(),
            "065eadf1-6daf-1543-b04f-10e69084c9ae"
        );
    }

    #[test]
    fn test_guid_make_macro() {
        let g = make_guid!("4b324fc8-1670-01d3-1278-5a47bf6ee188");
        assert_eq!(
            g,
            Guid(0x4b324fc8, 0x1670, 0x01d3, [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88])
        );
    }

    #[test]
    fn test_file_time_roundtrip() {
        let ft = FileTime::from(133818609802776324u64);
        let mut buf = Cursor::new(Vec::new());
        ft.write(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 8);
        let mut cursor = Cursor::new(&bytes[..]);
        let decoded: FileTime = FileTime::read(&mut cursor).unwrap();
        assert_eq!(decoded, ft);
        assert_eq!(*decoded, 133818609802776324u64);
    }

    #[test]
    fn test_file_time_zero() {
        let ft = FileTime::ZERO;
        assert!(ft.is_zero());
        assert_eq!(ft.as_u64(), 0);
    }

    #[test]
    fn test_boolean_roundtrip() {
        let mut buf = Cursor::new(Vec::new());
        Boolean::from(true).write(&mut buf).unwrap();
        Boolean::from(false).write(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(&bytes[..], &[0x01, 0x00]);

        let mut cursor = Cursor::new(&bytes[..]);
        let t: Boolean = Boolean::read(&mut cursor).unwrap();
        let f: Boolean = Boolean::read(&mut cursor).unwrap();
        assert_eq!(bool::from(t), true);
        assert_eq!(bool::from(f), false);
    }

    #[test]
    fn test_boolean_nonzero_is_true() {
        let mut cursor = Cursor::new(&[0x17u8][..]);
        let b: Boolean = Boolean::read(&mut cursor).unwrap();
        assert_eq!(bool::from(b), true);
    }
}