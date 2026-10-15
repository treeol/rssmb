//! SMB2 change notify and server-to-client notification messages.
//!
//! MS-SMB2 2.2.35–2.2.36, 2.2.44.

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use crate::create::FileId;

/// SMB2 CHANGE_NOTIFY Request.
///
/// MS-SMB2 2.2.35
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct ChangeNotifyRequest {
    #[bw(calc = 32)]
    structure_size: u16,
    pub flags: NotifyFlags,
    pub output_buffer_length: u32,
    pub file_id: FileId,
    pub completion_filter: NotifyFilter,
    #[bw(calc = 0)]
    #[br(temp)]
    reserved: u32,
}

/// Flags for CHANGE_NOTIFY.
///
/// MS-SMB2 2.2.35
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NotifyFlags {
    pub watch_tree: bool,
    #[skip]
    __: B15,
}

/// Completion filter for change notifications.
///
/// MS-SMB2 2.2.35
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NotifyFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,
    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,
    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
    pub stream_write: bool,
    #[skip]
    __: B20,
}

impl NotifyFilter {
    pub fn all() -> Self {
        Self::new()
            .with_file_name(true)
            .with_dir_name(true)
            .with_attributes(true)
            .with_size(true)
            .with_last_write(true)
            .with_last_access(true)
            .with_creation(true)
            .with_ea(true)
            .with_security(true)
            .with_stream_name(true)
            .with_stream_size(true)
            .with_stream_write(true)
    }
}

/// SMB2 CHANGE_NOTIFY Response.
///
/// MS-SMB2 2.2.36
#[binrw::binrw]
#[brw(little)]
#[derive(Debug, Default)]
pub struct ChangeNotifyResponse {
    #[bw(calc = 9)]
    structure_size: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _output_buffer_length: PosMarker<u32>,
    /// Change information (empty for PENDING response).
    #[br(seek_before = std::io::SeekFrom::Start(_output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(_output_buffer_length.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(if(!buffer.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_output_buffer_offset, &_output_buffer_length))]
    pub buffer: Vec<u8>,
}

use crate::dtyp::PosMarker;

/// SMB2 Server to Client Notification.
///
/// MS-SMB2 2.2.44.1
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct ServerToClientNotification {
    structure_size: u16,
    reserved: u16,
    #[bw(calc = notification.get_type())]
    notification_type: NotificationType,
    #[br(args(notification_type))]
    pub notification: Notification,
}

/// Notification type identifiers.
///
/// MS-SMB2 2.2.44.1
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u32))]
pub enum NotificationType {
    NotifySessionClosed = 0,
}

/// Notification structure.
///
/// MS-SMB2 2.2.44.1
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
#[br(import(notification_type: NotificationType))]
pub enum Notification {
    #[br(pre_assert(notification_type == NotificationType::NotifySessionClosed))]
    NotifySessionClosed(NotifySessionClosed),
}

impl Notification {
    pub fn get_type(&self) -> NotificationType {
        match self {
            Notification::NotifySessionClosed(_) => NotificationType::NotifySessionClosed,
        }
    }
}

/// Notify session closed structure.
///
/// MS-SMB2 2.2.44.2
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct NotifySessionClosed {
    reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use binrw::io::Cursor;

    #[test]
    fn test_change_notify_response_pending() {
        let resp = ChangeNotifyResponse { buffer: vec![] };
        let mut buf = Cursor::new(Vec::new());
        resp.write_le(&mut buf).unwrap();
        let bytes = buf.into_inner();
        assert_eq!(bytes.len(), 8); // StructureSize + offset + length
    }
}
