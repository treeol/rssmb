use super::*;

pub(crate) async fn send_break_notifications(breaks: &[opens::BreakNotification]) {
    for b in breaks {
        let (tx, content) = match b {
            opens::BreakNotification::Lease {
                notify_tx,
                lease_key,
                current_state,
                new_state,
                new_epoch,
                ack_required,
            } => (
                notify_tx,
                ResponseContent::LeaseBreakNotify(rssmb_proto::create::LeaseBreakNotify {
                    new_epoch: *new_epoch,
                    ack_required: u32::from(*ack_required),
                    lease_key: Guid::from(*lease_key),
                    current_lease_state: current_state.to_proto(),
                    new_lease_state: new_state.to_proto(),
                }),
            ),
            opens::BreakNotification::Oplock {
                notify_tx,
                smb_file_id,
                new_oplock_level,
            } => (
                notify_tx,
                ResponseContent::OplockBreakNotify(rssmb_proto::create::OplockBreakMsg {
                    oplock_level: *new_oplock_level,
                    reserved: 0,
                    _reserved2: 0,
                    file_id: *smb_file_id,
                }),
            ),
        };
        let plain = PlainResponse {
            header: Header {
                credit_charge: 0,
                status: NtStatus::Success.to_u32(),
                command: Command::OplockBreak,
                credit_request: 0,
                flags: HeaderFlags::new().with_server_to_redir(true),
                next_command: 0,
                message_id: u64::MAX,
                tree_id: Some(0),
                async_id: None,
                session_id: 0,
                signature: 0,
            },
            content,
        };
        let encoded = rssmb_wire_adapter::encode_response(&FramedResponse::Plain(plain));
        if !encoded.is_empty() {
            let _ = tx.send(encoded).await;
        }
    }
}

/// OPLOCK_BREAK — handle a client Oplock Break Acknowledgment or Lease Break
/// Acknowledgment (MS-SMB2 3.3.5.19.1 / 3.3.5.19.2).
pub(crate) async fn handle_oplock_break(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    // Validate that the session exists on this connection.
    let session_id = req.header.session_id;
    let session_exists = {
        let sessions = conn_state.sessions.read().await;
        sessions.iter().any(|s| s.id == session_id)
    };
    if !session_exists {
        return error_response_for(
            Command::OplockBreak,
            NtStatus::UserSessionDeleted,
            &req.header,
        );
    }

    match &req.content {
        RequestContent::LeaseBreakAck(ack) => {
            let client_guid = {
                let rec = conn_state.negotiate_record.lock().await;
                match &*rec {
                    Some(r) => {
                        let mut cg = [0u8; 16];
                        cg[0..4].copy_from_slice(&r.client_guid.0.to_le_bytes());
                        cg[4..6].copy_from_slice(&r.client_guid.1.to_le_bytes());
                        cg[6..8].copy_from_slice(&r.client_guid.2.to_le_bytes());
                        cg[8..16].copy_from_slice(&r.client_guid.3);
                        cg
                    }
                    None => [0u8; 16],
                }
            };
            let mut lease_key = [0u8; 16];
            lease_key[0..4].copy_from_slice(&ack.lease_key.0.to_le_bytes());
            lease_key[4..6].copy_from_slice(&ack.lease_key.1.to_le_bytes());
            lease_key[6..8].copy_from_slice(&ack.lease_key.2.to_le_bytes());
            lease_key[8..16].copy_from_slice(&ack.lease_key.3);

            let acked = opens::LeaseCaching::from_proto(ack.lease_state);
            match state
                .open_table
                .ack_lease_break(client_guid, lease_key, acked)
                .await
            {
                Ok((new_state, followup)) => {
                    if let Some(notif) = followup {
                        send_break_notifications(&[notif]).await;
                    }
                    let resp = rssmb_proto::create::LeaseBreakAckResponse {
                        reserved: 0,
                        _reserved2: 0,
                        lease_key: ack.lease_key,
                        lease_state: new_state.to_proto(),
                        _reserved3: 0,
                    };
                    FramedResponse::Plain(build_response(
                        &req.header,
                        ResponseContent::LeaseBreak(resp),
                    ))
                }
                Err(status) => error_response_for(Command::OplockBreak, status, &req.header),
            }
        }
        RequestContent::OplockBreakAck(ack) => {
            match state
                .open_table
                .ack_oplock_break(ack.file_id, ack.oplock_level)
                .await
            {
                Ok((new_level, followup)) => {
                    if let Some(notif) = followup {
                        send_break_notifications(&[notif]).await;
                    }
                    let resp = rssmb_proto::create::OplockBreakMsg {
                        oplock_level: new_level,
                        reserved: 0,
                        _reserved2: 0,
                        file_id: ack.file_id,
                    };
                    FramedResponse::Plain(build_response(
                        &req.header,
                        ResponseContent::OplockBreak(resp),
                    ))
                }
                Err(status) => error_response_for(Command::OplockBreak, status, &req.header),
            }
        }
        _ => error_response_for(
            Command::OplockBreak,
            NtStatus::InvalidParameter,
            &req.header,
        ),
    }
}
