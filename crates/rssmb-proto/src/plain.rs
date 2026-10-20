//! Plain SMB2 request/response — the command-discriminated union.
//!
//! MS-SMB2 2.2.1.1

use binrw::prelude::*;

use crate::cancel::CancelRequest;
use crate::create::{CloseRequest, CloseResponse, CreateRequest, CreateResponse};
use crate::echo::{EchoRequest, EchoResponse};
use crate::error::ErrorResponse;
use crate::file::{
    FlushRequest, FlushResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse,
};
use crate::header::{Command, Header};
use crate::info::{QueryInfoRequest, QueryInfoResponse, SetInfoRequest, SetInfoResponse};
use crate::negotiate::{NegotiateRequest, NegotiateResponse};
use crate::notify::{ChangeNotifyRequest, ChangeNotifyResponse, ServerToClientNotification};
use crate::oplock::{
    LeaseBreakAck, LeaseBreakNotify, LeaseBreakResponse, OplockBreakAck, OplockBreakNotify,
    OplockBreakResponse,
};
use crate::query_dir::{QueryDirectoryRequest, QueryDirectoryResponse};
use crate::session_setup::{
    LogoffRequest, LogoffResponse, SessionSetupRequest, SessionSetupResponse,
};
use crate::tree_connect::{
    TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse,
};

/// Contains all the variants for a plain SMB2 request message.
#[binrw::binrw]
#[derive(Debug)]
#[brw(import(command: &Command), little)]
pub enum RequestContent {
    #[br(pre_assert(matches!(command, Command::Negotiate)))]
    Negotiate(NegotiateRequest),
    #[br(pre_assert(matches!(command, Command::SessionSetup)))]
    SessionSetup(SessionSetupRequest),
    #[br(pre_assert(matches!(command, Command::Logoff)))]
    Logoff(LogoffRequest),
    #[br(pre_assert(matches!(command, Command::TreeConnect)))]
    TreeConnect(TreeConnectRequest),
    #[br(pre_assert(matches!(command, Command::TreeDisconnect)))]
    TreeDisconnect(TreeDisconnectRequest),
    #[br(pre_assert(matches!(command, Command::Create)))]
    Create(CreateRequest),
    #[br(pre_assert(matches!(command, Command::Close)))]
    Close(CloseRequest),
    #[br(pre_assert(matches!(command, Command::Flush)))]
    Flush(FlushRequest),
    #[br(pre_assert(matches!(command, Command::Read)))]
    Read(ReadRequest),
    #[br(pre_assert(matches!(command, Command::Write)))]
    Write(WriteRequest),
    #[br(pre_assert(matches!(command, Command::Echo)))]
    Echo(EchoRequest),
    #[br(pre_assert(matches!(command, Command::QueryDirectory)))]
    QueryDirectory(QueryDirectoryRequest),
    #[br(pre_assert(matches!(command, Command::ChangeNotify)))]
    ChangeNotify(ChangeNotifyRequest),
    #[br(pre_assert(matches!(command, Command::QueryInfo)))]
    QueryInfo(QueryInfoRequest),
    #[br(pre_assert(matches!(command, Command::SetInfo)))]
    SetInfo(SetInfoRequest),
    #[br(pre_assert(matches!(command, Command::Ioctl)))]
    Ioctl(crate::ioctl::IoctlRequest),
    #[br(pre_assert(matches!(command, Command::Lock)))]
    Lock(crate::lock::LockRequest),
    #[br(pre_assert(matches!(command, Command::Cancel)))]
    Cancel(CancelRequest),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    OplockBreakAck(OplockBreakAck),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    LeaseBreakAck(LeaseBreakAck),
}

impl RequestContent {
    pub fn associated_cmd(&self) -> Command {
        match self {
            RequestContent::Negotiate(_) => Command::Negotiate,
            RequestContent::SessionSetup(_) => Command::SessionSetup,
            RequestContent::Logoff(_) => Command::Logoff,
            RequestContent::TreeConnect(_) => Command::TreeConnect,
            RequestContent::TreeDisconnect(_) => Command::TreeDisconnect,
            RequestContent::Create(_) => Command::Create,
            RequestContent::Close(_) => Command::Close,
            RequestContent::Flush(_) => Command::Flush,
            RequestContent::Read(_) => Command::Read,
            RequestContent::Write(_) => Command::Write,
            RequestContent::Echo(_) => Command::Echo,
            RequestContent::QueryDirectory(_) => Command::QueryDirectory,
            RequestContent::ChangeNotify(_) => Command::ChangeNotify,
            RequestContent::QueryInfo(_) => Command::QueryInfo,
            RequestContent::SetInfo(_) => Command::SetInfo,
            RequestContent::Ioctl(_) => Command::Ioctl,
            RequestContent::Lock(_) => Command::Lock,
            RequestContent::Cancel(_) => Command::Cancel,
            RequestContent::OplockBreakAck(_) | RequestContent::LeaseBreakAck(_) => {
                Command::OplockBreak
            }
        }
    }
}

/// Contains all the variants for a plain SMB2 response message.
#[binrw::binrw]
#[derive(Debug)]
#[brw(import(command: &Command), little)]
pub enum ResponseContent {
    #[br(pre_assert(matches!(command, Command::Negotiate)))]
    Negotiate(NegotiateResponse),
    #[br(pre_assert(matches!(command, Command::SessionSetup)))]
    SessionSetup(SessionSetupResponse),
    #[br(pre_assert(matches!(command, Command::Logoff)))]
    Logoff(LogoffResponse),
    #[br(pre_assert(matches!(command, Command::TreeConnect)))]
    TreeConnect(TreeConnectResponse),
    #[br(pre_assert(matches!(command, Command::TreeDisconnect)))]
    TreeDisconnect(TreeDisconnectResponse),
    #[br(pre_assert(matches!(command, Command::Create)))]
    Create(CreateResponse),
    #[br(pre_assert(matches!(command, Command::Close)))]
    Close(CloseResponse),
    #[br(pre_assert(matches!(command, Command::Flush)))]
    Flush(FlushResponse),
    #[br(pre_assert(matches!(command, Command::Read)))]
    Read(ReadResponse),
    #[br(pre_assert(matches!(command, Command::Write)))]
    Write(WriteResponse),
    #[br(pre_assert(matches!(command, Command::Echo)))]
    Echo(EchoResponse),
    #[br(pre_assert(matches!(command, Command::QueryDirectory)))]
    QueryDirectory(QueryDirectoryResponse),
    #[br(pre_assert(matches!(command, Command::ChangeNotify)))]
    ChangeNotify(ChangeNotifyResponse),
    #[br(pre_assert(matches!(command, Command::QueryInfo)))]
    QueryInfo(QueryInfoResponse),
    #[br(pre_assert(matches!(command, Command::SetInfo)))]
    SetInfo(SetInfoResponse),
    #[br(pre_assert(matches!(command, Command::Ioctl)))]
    Ioctl(crate::ioctl::IoctlResponse),
    #[br(pre_assert(matches!(command, Command::Lock)))]
    Lock(crate::lock::LockResponse),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    OplockBreakNotify(OplockBreakNotify),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    LeaseBreakNotify(LeaseBreakNotify),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    OplockBreak(OplockBreakResponse),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    LeaseBreak(LeaseBreakResponse),
    #[br(pre_assert(matches!(command, Command::ServerToClientNotification)))]
    ServerToClientNotification(ServerToClientNotification),
    /// Error response — no matching command.
    Error(ErrorResponse),
}

impl ResponseContent {
    pub fn associated_cmd(&self) -> Command {
        match self {
            ResponseContent::Negotiate(_) => Command::Negotiate,
            ResponseContent::SessionSetup(_) => Command::SessionSetup,
            ResponseContent::Logoff(_) => Command::Logoff,
            ResponseContent::TreeConnect(_) => Command::TreeConnect,
            ResponseContent::TreeDisconnect(_) => Command::TreeDisconnect,
            ResponseContent::Create(_) => Command::Create,
            ResponseContent::Close(_) => Command::Close,
            ResponseContent::Flush(_) => Command::Flush,
            ResponseContent::Read(_) => Command::Read,
            ResponseContent::Write(_) => Command::Write,
            ResponseContent::Echo(_) => Command::Echo,
            ResponseContent::QueryDirectory(_) => Command::QueryDirectory,
            ResponseContent::ChangeNotify(_) => Command::ChangeNotify,
            ResponseContent::QueryInfo(_) => Command::QueryInfo,
            ResponseContent::SetInfo(_) => Command::SetInfo,
            ResponseContent::Ioctl(_) => Command::Ioctl,
            ResponseContent::Lock(_) => Command::Lock,
            ResponseContent::OplockBreakNotify(_)
            | ResponseContent::OplockBreak(_)
            | ResponseContent::LeaseBreakNotify(_)
            | ResponseContent::LeaseBreak(_) => Command::OplockBreak,
            ResponseContent::ServerToClientNotification(_) => Command::ServerToClientNotification,
            ResponseContent::Error(_) => Command::Create, // placeholder — build_response uses req_header.command for Error
        }
    }
}

// From impls for common request types.
impl From<NegotiateRequest> for RequestContent {
    fn from(v: NegotiateRequest) -> Self {
        RequestContent::Negotiate(v)
    }
}
impl From<SessionSetupRequest> for RequestContent {
    fn from(v: SessionSetupRequest) -> Self {
        RequestContent::SessionSetup(v)
    }
}
impl From<LogoffRequest> for RequestContent {
    fn from(v: LogoffRequest) -> Self {
        RequestContent::Logoff(v)
    }
}
impl From<TreeConnectRequest> for RequestContent {
    fn from(v: TreeConnectRequest) -> Self {
        RequestContent::TreeConnect(v)
    }
}
impl From<TreeDisconnectRequest> for RequestContent {
    fn from(v: TreeDisconnectRequest) -> Self {
        RequestContent::TreeDisconnect(v)
    }
}
impl From<CreateRequest> for RequestContent {
    fn from(v: CreateRequest) -> Self {
        RequestContent::Create(v)
    }
}
impl From<CloseRequest> for RequestContent {
    fn from(v: CloseRequest) -> Self {
        RequestContent::Close(v)
    }
}
impl From<FlushRequest> for RequestContent {
    fn from(v: FlushRequest) -> Self {
        RequestContent::Flush(v)
    }
}
impl From<ReadRequest> for RequestContent {
    fn from(v: ReadRequest) -> Self {
        RequestContent::Read(v)
    }
}
impl From<WriteRequest> for RequestContent {
    fn from(v: WriteRequest) -> Self {
        RequestContent::Write(v)
    }
}
impl From<EchoRequest> for RequestContent {
    fn from(v: EchoRequest) -> Self {
        RequestContent::Echo(v)
    }
}
impl From<QueryDirectoryRequest> for RequestContent {
    fn from(v: QueryDirectoryRequest) -> Self {
        RequestContent::QueryDirectory(v)
    }
}
impl From<ChangeNotifyRequest> for RequestContent {
    fn from(v: ChangeNotifyRequest) -> Self {
        RequestContent::ChangeNotify(v)
    }
}
impl From<QueryInfoRequest> for RequestContent {
    fn from(v: QueryInfoRequest) -> Self {
        RequestContent::QueryInfo(v)
    }
}
impl From<SetInfoRequest> for RequestContent {
    fn from(v: SetInfoRequest) -> Self {
        RequestContent::SetInfo(v)
    }
}
impl From<crate::ioctl::IoctlRequest> for RequestContent {
    fn from(v: crate::ioctl::IoctlRequest) -> Self {
        RequestContent::Ioctl(v)
    }
}
impl From<crate::lock::LockRequest> for RequestContent {
    fn from(v: crate::lock::LockRequest) -> Self {
        RequestContent::Lock(v)
    }
}
impl From<CancelRequest> for RequestContent {
    fn from(v: CancelRequest) -> Self {
        RequestContent::Cancel(v)
    }
}

// From impls for common response types.
impl From<NegotiateResponse> for ResponseContent {
    fn from(v: NegotiateResponse) -> Self {
        ResponseContent::Negotiate(v)
    }
}
impl From<SessionSetupResponse> for ResponseContent {
    fn from(v: SessionSetupResponse) -> Self {
        ResponseContent::SessionSetup(v)
    }
}
impl From<LogoffResponse> for ResponseContent {
    fn from(v: LogoffResponse) -> Self {
        ResponseContent::Logoff(v)
    }
}
impl From<TreeConnectResponse> for ResponseContent {
    fn from(v: TreeConnectResponse) -> Self {
        ResponseContent::TreeConnect(v)
    }
}
impl From<TreeDisconnectResponse> for ResponseContent {
    fn from(v: TreeDisconnectResponse) -> Self {
        ResponseContent::TreeDisconnect(v)
    }
}
impl From<CreateResponse> for ResponseContent {
    fn from(v: CreateResponse) -> Self {
        ResponseContent::Create(v)
    }
}
impl From<CloseResponse> for ResponseContent {
    fn from(v: CloseResponse) -> Self {
        ResponseContent::Close(v)
    }
}
impl From<FlushResponse> for ResponseContent {
    fn from(v: FlushResponse) -> Self {
        ResponseContent::Flush(v)
    }
}
impl From<ReadResponse> for ResponseContent {
    fn from(v: ReadResponse) -> Self {
        ResponseContent::Read(v)
    }
}
impl From<WriteResponse> for ResponseContent {
    fn from(v: WriteResponse) -> Self {
        ResponseContent::Write(v)
    }
}
impl From<EchoResponse> for ResponseContent {
    fn from(v: EchoResponse) -> Self {
        ResponseContent::Echo(v)
    }
}
impl From<QueryDirectoryResponse> for ResponseContent {
    fn from(v: QueryDirectoryResponse) -> Self {
        ResponseContent::QueryDirectory(v)
    }
}
impl From<ChangeNotifyResponse> for ResponseContent {
    fn from(v: ChangeNotifyResponse) -> Self {
        ResponseContent::ChangeNotify(v)
    }
}
impl From<QueryInfoResponse> for ResponseContent {
    fn from(v: QueryInfoResponse) -> Self {
        ResponseContent::QueryInfo(v)
    }
}
impl From<SetInfoResponse> for ResponseContent {
    fn from(v: SetInfoResponse) -> Self {
        ResponseContent::SetInfo(v)
    }
}
impl From<crate::ioctl::IoctlResponse> for ResponseContent {
    fn from(v: crate::ioctl::IoctlResponse) -> Self {
        ResponseContent::Ioctl(v)
    }
}
impl From<crate::lock::LockResponse> for ResponseContent {
    fn from(v: crate::lock::LockResponse) -> Self {
        ResponseContent::Lock(v)
    }
}
impl From<ErrorResponse> for ResponseContent {
    fn from(v: ErrorResponse) -> Self {
        ResponseContent::Error(v)
    }
}

/// A plain, single SMB2 request message.
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct PlainRequest {
    #[brw(assert(!header.flags.server_to_redir()))]
    pub header: Header,
    #[brw(args(&header.command))]
    pub content: RequestContent,
}

/// A plain, single SMB2 response message.
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
pub struct PlainResponse {
    #[brw(assert(header.flags.server_to_redir()))]
    pub header: Header,
    #[brw(args(&header.command))]
    pub content: ResponseContent,
}
