use super::*;

pub(crate) async fn pend_until_breaks(
    conn_state: &ConnState,
    req_header: &Header,
    waiters: Vec<opens::BreakWaiter>,
    command: Command,
    outcome: Result<ResponseContent, NtStatus>,
) -> FramedResponse {
    let message_id = req_header.message_id;
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    conn_state.pending_async.lock().await.insert(
        message_id,
        AsyncOp {
            command,
            session_id: req_header.session_id,
            tree_id: req_header.tree_id.unwrap_or(0),
            cancel: cancel_tx,
            notify_handle: None,
            watched_file_id: None,
            lock_open_volatile: None,
        },
    );
    let mut pending_hdr = req_header.clone();
    pending_hdr.status = NtStatus::Pending.to_u32();
    pending_hdr.to_async(message_id);
    pending_hdr.flags = pending_hdr.flags.with_server_to_redir(true);
    let pending_resp = PlainResponse {
        header: pending_hdr,
        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
    };
    let conn_clone = conn_state.clone();
    let req_header = req_header.clone();
    tokio::spawn(async move {
        let wait_all = futures::future::join_all(waiters.into_iter().map(|w| w.receiver));
        let safety_timeout = tokio::time::sleep(std::time::Duration::from_secs(36));
        tokio::pin!(wait_all);
        tokio::pin!(safety_timeout);
        tokio::select! {
            _ = wait_all => {}
            _ = safety_timeout => {}
            _ = cancel_rx => {
                conn_clone.pending_async.lock().await.remove(&message_id);
                return;
            }
        }
        conn_clone.pending_async.lock().await.remove(&message_id);
        let (content, status) = match outcome {
            Ok(c) => (c, NtStatus::Success),
            Err(s) => (
                ResponseContent::Error(rssmb_proto::error::ErrorResponse { error_data: vec![] }),
                s,
            ),
        };
        let mut resp = build_response(&req_header, content);
        resp.header.to_async(message_id);
        resp.header.status = status.to_u32();
        resp.header.credit_charge = 0;
        resp.header.credit_request = 0;
        send_unsolicited(&conn_clone, &FramedResponse::Plain(resp), true).await;
    });
    FramedResponse::Plain(pending_resp)
}

pub(crate) async fn send_unsolicited(
    conn_state: &ConnState,
    resp: &FramedResponse,
    client_signed: bool,
) {
    let mut bytes = rssmb_wire_adapter::encode_response(resp).to_vec();
    if bytes.is_empty() {
        tracing::warn!(
            conn_id = conn_state.conn_id,
            "send_unsolicited: nothing to send"
        );
        return;
    }

    // Snapshot the encryption state once (avoid TOCTOU between the
    // encrypt_data check and the key lookup).
    let enc_state_snap: Option<EncryptionState> = match resp {
        FramedResponse::Plain(p) => {
            let sid = p.header.session_id;
            if sid == 0 {
                None
            } else {
                conn_state
                    .encryption_ref()
                    .read()
                    .unwrap()
                    .get(&sid)
                    .filter(|st| st.encrypt_data)
                    .cloned()
            }
        }
        _ => None,
    };

    // Sign only when NOT encrypting. When encrypting, the AEAD provides
    // integrity; the SIGNED flag and signature are cleared before
    // encryption.
    if enc_state_snap.is_none() {
        crate::signing::sign_response_frame(
            &mut bytes,
            &[client_signed],
            |sid| conn_state.signing_ref().read().unwrap().get(&sid).cloned(),
            |_| {},
        );
    }

    let bytes = if let Some(st) = enc_state_snap {
        // Clear SIGNED flag and zero signatures before encryption.
        let body = &mut bytes[4..];
        let ranges = rssmb_wire_adapter::framing::message_ranges(body);
        for (s, e) in &ranges {
            let msg = &mut body[*s..*e];
            let flags = u32::from_le_bytes(msg[16..20].try_into().unwrap());
            let flags = flags & !0x0000_0008;
            msg[16..20].copy_from_slice(&flags.to_le_bytes());
            let sig_end = 64.min(msg.len());
            msg[48..sig_end].fill(0);
        }

        let sid = match resp {
            FramedResponse::Plain(p) => p.header.session_id,
            _ => 0,
        };
        let smb2_body = &bytes[4..];
        let mut plaintext = smb2_body.to_vec();
        let nonce = match st.nonce_source.next() {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(conn_id = conn_state.conn_id,
                    error = %e, "send_unsolicited: nonce exhausted");
                return;
            }
        };
        let orig_len = plaintext.len() as u32;
        match crate::crypto::encrypt_message(&st.enc_key, &nonce, orig_len, sid, &mut plaintext) {
            Ok((hdr, tag)) => {
                let mut wire = Vec::with_capacity(4 + 52 + plaintext.len());
                let nb_len = (52 + plaintext.len()) as u32;
                wire.push(0x00);
                wire.push((nb_len >> 16) as u8);
                wire.push((nb_len >> 8) as u8);
                wire.push(nb_len as u8);
                let mut full_hdr = hdr;
                full_hdr[4..20].copy_from_slice(&tag);
                wire.extend_from_slice(&full_hdr);
                wire.extend_from_slice(&plaintext);
                Bytes::from(wire)
            }
            Err(e) => {
                tracing::warn!(conn_id = conn_state.conn_id,
                    error = %e, "send_unsolicited: encryption failed");
                return;
            }
        }
    } else {
        Bytes::from(bytes)
    };

    let _ = conn_state.write_tx.send(bytes).await;
}
