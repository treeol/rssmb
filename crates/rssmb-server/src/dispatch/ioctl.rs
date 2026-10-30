use super::*;

pub(crate) async fn handle_ioctl(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let io = match &req.content {
        RequestContent::Ioctl(i) => i,
        _ => return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header),
    };
    const FSCTL_DFS_GET_REFERRALS: u32 = 0x0006_0194;
    const FSCTL_DFS_GET_REFERRALS_EX: u32 = 0x0006_01B0;
    const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
    const FSCTL_LMR_REQ_RESILIENCY: u32 = 0x0014_01F4;
    const FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
    const FSCTL_CREATE_OR_GET_OBJECT_ID: u32 = 0x0009_00C0;
    const STATUS_NOT_FOUND: u32 = 0xC000_0225;
    const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    debug!(
        conn_id = conn_state.conn_id,
        ctl_code = format!("{:#010x}", io.ctl_code),
        "ioctl"
    );

    // FSCTL_PIPE_TRANSCEIVE: write input to the pipe, read output back.
    // Only valid on pipe opens (named pipes on IPC$).
    if io.ctl_code == FSCTL_PIPE_TRANSCEIVE {
        let file_id_volatile = io.file_id.volatile;
        let session_id = req.header.session_id;
        let tree_id = req.header.tree_id.unwrap_or(0);
        let entry = match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile)
            .await
        {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::Ioctl, status, &req.header),
        };
        if !entry.is_pipe {
            return error_response_for(
                Command::Ioctl,
                NtStatus::Other(STATUS_INVALID_DEVICE_REQUEST),
                &req.header,
            );
        }
        let ps = entry
            .pipe_state
            .as_ref()
            .expect("pipe open without pipe_state");
        let identity = lookup_session_identity(conn_state, session_id).await;
        let shares = visible_shares_for_ctx(&state.shares_snapshot(), identity.as_ref());
        let server_name = if !state.config.server_name.is_empty() {
            &state.config.server_name
        } else {
            "rssmb"
        };
        let rpc_ctx = rssmb_rpc_server::RpcCtx {
            username: identity.as_ref().map(|i| i.username.as_str()).unwrap_or(""),
            is_guest: identity.as_ref().map(|i| i.is_guest).unwrap_or(false),
            shares,
            server_name,
        };

        // Extract input buffer from the IOCTL request.
        let input_data: Vec<u8> = match &io.buffer {
            rssmb_proto::ioctl::IoctlReqData::FsctlPipeTransceive(buf) => buf.as_slice().to_vec(),
            _ => vec![],
        };

        let max_output = io.max_output_response as usize;
        let mut state = ps.lock().unwrap();
        if !input_data.is_empty() {
            let _consumed = state.process(&input_data, &rpc_ctx);
        }
        let (output, read_status) = state.read(max_output);

        if output.is_empty() {
            return error_response_for(Command::Ioctl, NtStatus::PipeEmpty, &req.header);
        }

        let ioctl_resp = rssmb_proto::ioctl::IoctlResponse {
            ctl_code: io.ctl_code,
            file_id: io.file_id,
            in_buffer: vec![],
            out_buffer: output,
        };
        let mut response = build_response(&req.header, ResponseContent::Ioctl(ioctl_resp));
        if read_status == rssmb_rpc_server::ReadStatus::Overflow {
            response.header.status = NtStatus::BufferOverflow.to_u32();
        }
        return FramedResponse::Plain(response);
    }

    let status = match io.ctl_code {
        FSCTL_VALIDATE_NEGOTIATE_INFO => {
            let rec_guard = conn_state.negotiate_record.lock().await;
            let Some(rec) = &*rec_guard else {
                return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header);
            };
            // MS-SMB2 3.3.5.15.12: VNI is only defined for SMB 3.0/3.0.2.
            // For other dialects, return STATUS_NOT_SUPPORTED (or the
            // spec's behavior for non-applicable dialects).
            if !matches!(rec.dialect, DialectConfig::Smb30 | DialectConfig::Smb302) {
                return error_response_for(Command::Ioctl, NtStatus::NotSupported, &req.header);
            }
            match &io.buffer {
                rssmb_proto::ioctl::IoctlReqData::FsctlValidateNegotiateInfo(vni) => {
                    if vni.capabilities != u32::from_le_bytes(rec.client_capabilities.into_bytes())
                    {
                        warn!(conn_id = conn_state.conn_id, "VNI capabilities mismatch");
                        return FramedResponse::Disconnect;
                    }
                    if vni.guid != rec.client_guid {
                        warn!(conn_id = conn_state.conn_id, "VNI GUID mismatch");
                        return FramedResponse::Disconnect;
                    }
                    if vni.security_mode != rec.client_security_mode {
                        warn!(conn_id = conn_state.conn_id, "VNI security mode mismatch");
                        return FramedResponse::Disconnect;
                    }
                    let vni_dialects: Vec<WireDialect> = vni
                        .dialects
                        .iter()
                        .map(|d| match d.dialect {
                            0x0202 => WireDialect::Smb0202,
                            0x0210 => WireDialect::Smb021,
                            0x0300 => WireDialect::Smb030,
                            0x0302 => WireDialect::Smb0302,
                            0x0311 => WireDialect::Smb0311,
                            _ => WireDialect::Smb0202,
                        })
                        .collect();
                    let reselected = select_dialect(
                        &vni_dialects,
                        state.config.min_dialect,
                        state.config.max_dialect,
                    );
                    if reselected != Some(rec.dialect) {
                        warn!(
                            conn_id = conn_state.conn_id,
                            "VNI dialect re-selection mismatch"
                        );
                        return FramedResponse::Disconnect;
                    }
                    let out = rssmb_proto::ioctl::ValidateNegotiateInfoResponse {
                        capabilities: u32::from_le_bytes(rec.server_capabilities.into_bytes()),
                        guid: Guid::from(state.server_guid),
                        security_mode: rec.server_security_mode,
                        dialect: rec.wire_dialect(),
                    };
                    use binrw::BinWrite;
                    let mut buf = std::io::Cursor::new(Vec::new());
                    if out.write_le(&mut buf).is_err() {
                        return error_response_for(
                            Command::Ioctl,
                            NtStatus::InvalidParameter,
                            &req.header,
                        );
                    }
                    let resp = rssmb_proto::ioctl::IoctlResponse {
                        ctl_code: io.ctl_code,
                        file_id: io.file_id,
                        in_buffer: vec![],
                        out_buffer: buf.into_inner(),
                    };
                    return FramedResponse::Plain(build_response(
                        &req.header,
                        ResponseContent::Ioctl(resp),
                    ));
                }
                _ => {
                    return error_response_for(
                        Command::Ioctl,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            }
        }
        FSCTL_DFS_GET_REFERRALS | FSCTL_DFS_GET_REFERRALS_EX => NtStatus::Other(STATUS_NOT_FOUND),
        FSCTL_QUERY_NETWORK_INTERFACE_INFO => {
            // MS-SMB2 2.2.32.5 / 3.3.5.15.11: return the server's network
            // interface addresses so the client can establish additional
            // channels (multichannel). Requires SMB 3.0+ and a multichannel-
            // capable server.
            let rec_guard = conn_state.negotiate_record.lock().await;
            let Some(rec) = &*rec_guard else {
                return error_response_for(Command::Ioctl, NtStatus::InvalidParameter, &req.header);
            };
            // QNII is defined for SMB 3.x only.
            if rec.dialect < DialectConfig::Smb30 {
                return error_response_for(Command::Ioctl, NtStatus::NotSupported, &req.header);
            }
            if !state.config.multichannel {
                NtStatus::NotSupported
            } else {
                let addresses = state.interface_snapshot.get();
                if addresses.is_empty() {
                    NtStatus::NotSupported
                } else {
                    let interfaces = crate::netinfo::to_network_interface_infos(&addresses);
                    let mut buf = rssmb_proto::ioctl::serialize_network_interface_list(&interfaces);
                    // Truncate at entry boundaries if the client's
                    // MaxOutputResponse cannot hold the full list, and
                    // return STATUS_BUFFER_OVERFLOW with the truncated data.
                    let max_output = io.max_output_response as usize;
                    let entry_size = rssmb_proto::ioctl::NETWORK_INTERFACE_INFO_SIZE;
                    let mut overflow = false;
                    if buf.len() > max_output {
                        let fit = max_output / entry_size;
                        if fit == 0 {
                            // Not even one entry fits: STATUS_BUFFER_TOO_SMALL
                            // with no data (a warning + empty buffer would
                            // read as "server has zero interfaces").
                            return error_response_for(
                                Command::Ioctl,
                                NtStatus::BufferTooSmall,
                                &req.header,
                            );
                        }
                        buf.truncate(fit * entry_size);
                        overflow = true;
                        // Fix the new last entry's Next to 0.
                        let last = buf.len() - entry_size;
                        buf[last..last + 4].fill(0);
                    }
                    let resp = rssmb_proto::ioctl::IoctlResponse {
                        ctl_code: io.ctl_code,
                        file_id: io.file_id,
                        in_buffer: vec![],
                        out_buffer: buf,
                    };
                    let mut response = build_response(&req.header, ResponseContent::Ioctl(resp));
                    if overflow {
                        response.header.status = NtStatus::BufferOverflow.to_u32();
                    }
                    return FramedResponse::Plain(response);
                }
            }
        }
        FSCTL_LMR_REQ_RESILIENCY => {
            // MS-SMB2 3.3.5.15.15: client asks the server to make the open
            // resilient (min 1 s timeout in the 8-byte input). We have no
            // durable-handle wipe on connection loss for plain opens, so
            // this is a validated no-op: require a live file handle and
            // reply OK (torture replay_broken_windows asserts OK at
            // lock.c:2992; the old fall-through returned
            // INVALID_DEVICE_REQUEST).
            let file_id_volatile = io.file_id.volatile;
            let session_id = req.header.session_id;
            let tree_id = req.header.tree_id.unwrap_or(0);
            if let Err(status) =
                lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await
            {
                return error_response_for(Command::Ioctl, status, &req.header);
            }
            NtStatus::Success
        }
        FSCTL_CREATE_OR_GET_OBJECT_ID => {
            // Samba source3/modules/vfs_default.c:1466 — return the file's
            // object ID (dev+ino). Layout: file_id (16) + volume objectid
            // (16) + file_id (16) + zero (16) = 64 bytes. smb2.compound
            // related3 chains CREATE + this ioctl + CLOSE and expects OK.
            let file_id_volatile = io.file_id.volatile;
            let session_id = req.header.session_id;
            let tree_id = req.header.tree_id.unwrap_or(0);
            let Ok(entry) =
                lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await
            else {
                // Unknown handle → FILE_CLOSED (Samba smb2_ioctl.c default:
                // file_fsp_smb2() == NULL → FILE_CLOSED, not
                // INVALID_DEVICE_REQUEST).
                return error_response_for(Command::Ioctl, NtStatus::FileClosed, &req.header);
            };
            let fid = entry
                .file_id
                .unwrap_or(rssmb_vfs::FileId { dev: 0, ino: 0 });
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&fid.dev.to_le_bytes());
            out.extend_from_slice(&fid.ino.to_le_bytes());
            // Volume objectid: zero (Samba uses create_volume_objectid —
            // opaque per share; zero is a valid stable value).
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&fid.dev.to_le_bytes());
            out.extend_from_slice(&fid.ino.to_le_bytes());
            out.extend_from_slice(&[0u8; 16]);
            out.resize(64.min(io.max_output_response as usize), 0);
            let resp = rssmb_proto::ioctl::IoctlResponse {
                ctl_code: io.ctl_code,
                file_id: io.file_id,
                in_buffer: vec![],
                out_buffer: out,
            };
            return FramedResponse::Plain(build_response(
                &req.header,
                ResponseContent::Ioctl(resp),
            ));
        }
        _ => {
            // Unknown FSCTL on a live handle: FILE_CLOSED when the handle
            // does not exist (Samba smb2_ioctl.c: file_fsp_smb2() == NULL →
            // FILE_CLOSED; smb2.compound related5), else
            // INVALID_DEVICE_REQUEST (the unimplemented-FSCTL default).
            let file_id_volatile = io.file_id.volatile;
            let session_id = req.header.session_id;
            let tree_id = req.header.tree_id.unwrap_or(0);
            match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
                Ok(_) => NtStatus::Other(STATUS_INVALID_DEVICE_REQUEST),
                Err(_) => NtStatus::FileClosed,
            }
        }
    };
    error_response_for(Command::Ioctl, status, &req.header)
}
