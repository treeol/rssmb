use super::*;

pub(crate) async fn handle_session_setup(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
    raw_msg: &[u8],
) -> FramedResponse {
    // Extract the session setup request content
    let session_setup_req = match &req.content {
        RequestContent::SessionSetup(ss) => ss,
        _ => {
            return error_response_for(
                Command::SessionSetup,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    // Auth throttle: if the source IP is in cooldown from too many recent
    // failures, refuse SESSION_SETUP immediately. This check runs before
    // any auth processing so it costs the attacker nothing but a LOGON_FAILURE.
    // Only applies to new auth conversations (SessionId == 0); continuation
    // rounds for an already-pending session are not throttled.
    if req.header.session_id == 0 {
        match state.auth_limiter.check(&conn_state.remote_addr) {
            crate::auth_limiter::AuthThrottleResult::Refuse => {
                // Count this as a per-connection failure too — a connection
                // that keeps trying during cooldown should hit the per-conn
                // cap and get disconnected, not spin forever.
                let conn_fails = conn_state
                    .auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                tracing::warn!(
                    conn_id = conn_state.conn_id,
                    ip = %conn_state.remote_addr,
                    conn_failures = conn_fails,
                    "SESSION_SETUP refused — auth cooldown active",
                );
                if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                    warn!(
                        conn_id = conn_state.conn_id,
                        conn_failures = conn_fails,
                        "per-connection auth failure cap exceeded — disconnecting"
                    );
                    return FramedResponse::Disconnect;
                }
                return error_response_for(
                    Command::SessionSetup,
                    NtStatus::LogonFailure,
                    &req.header,
                );
            }
            crate::auth_limiter::AuthThrottleResult::Allow => {}
        }
    }

    // Get or create auth state
    let mut auth_guard = conn_state.auth_state.lock().await;
    let auth_state = auth_guard.get_or_insert_with(rssmb_auth::AuthState::new);

    // Create the NTLM auth provider with server-side credentials from
    // ServerState. The identity store is built once at startup with
    // pre-computed NT hashes — no plaintext passwords are rebuilt per
    // SESSION_SETUP. Guest fallback is gated on config.guest_access.
    // Guest/anonymous sessions have no key and can never be signed, so
    // `signing = "required"` disables them (as Windows does).
    let guest_allowed =
        state.config.guest_access && state.config.signing != crate::config::SigningPolicy::Required;
    let provider: Box<dyn rssmb_auth::AuthProvider> =
        Box::new(rssmb_auth::NtlmAuthProvider::with_identity_store_and_flags(
            state.identities_snapshot(),
            guest_allowed,
            state.config.ntlm_require_timestamp,
            state.config.ntlm_max_clock_skew_secs,
        ));

    // Extract the security buffer from the session setup request
    let input_token = &session_setup_req.buffer;

    // MS-SMB2 3.3.5.5: a SESSION_SETUP with SessionId == 0 starts a new
    // session; the server must assign a non-zero SessionId in its response,
    // which the client then echoes on subsequent rounds.
    // One authentication conversation per connection at a time (the acceptor
    // state is connection-wide). Its SessionId is the only pending one.
    let session_id = if req.header.session_id == 0 {
        // A fresh authentication: discard any stale per-connection auth state
        // and invalidate the SessionId it was bound to.
        *auth_state = rssmb_auth::AuthState::new();
        let new_id = next_session_id(conn_state, state);
        let mut pending = conn_state.pending_sessions.write().await;
        pending.clear();
        pending.insert(new_id);
        // Clear stale preauth session entries from abandoned auth attempts.
        conn_state.preauth_sessions.lock().unwrap().clear();
        // SMB 3.1.1: fork the connection preauth hash into a per-session hash.
        let is_311 = conn_state
            .negotiate_record
            .lock()
            .await
            .as_ref()
            .map(|r| r.dialect == DialectConfig::Smb311)
            .unwrap_or(false);
        if is_311 {
            let conn_hash = *conn_state.preauth_conn.lock().unwrap();
            if let Some(ch) = conn_hash {
                conn_state
                    .preauth_sessions
                    .lock()
                    .unwrap()
                    .insert(new_id, ch);
            }
        }
        new_id
    } else if conn_state
        .pending_sessions
        .read()
        .await
        .contains(&req.header.session_id)
    {
        req.header.session_id
    } else if session_setup_req.flags.binding()
        && req.header.session_id != 0
        && state.config.multichannel
    {
        // SMB 3.x multichannel binding (MS-SMB2 3.3.5.5):
        // A second connection binds to an existing session. The request
        // must be signed with the existing session's signing key.
        let session_id = req.header.session_id;

        // Look up the existing session in the global registry.
        let existing_shared = state
            .session_registry
            .read()
            .unwrap()
            .get(&session_id)
            .cloned();
        let existing_session = {
            let sessions = conn_state.sessions.read().await;
            sessions.iter().find(|s| s.id == session_id).cloned()
        };

        // The session must exist in the global registry (not just locally).
        let shared = match existing_shared {
            Some(ss) => ss,
            None => {
                warn!(
                    conn_id = conn_state.conn_id,
                    session_id, "binding: session not found in global registry"
                );
                return error_response_for(
                    Command::SessionSetup,
                    NtStatus::UserSessionDeleted,
                    &req.header,
                );
            }
        };

        // Verify the binding request is signed with the existing session's key.
        // The signing verification already happened in the connection read loop
        // (signing::verify_frame). If we got here, the signature was valid.
        // MS-SMB2 3.3.5.5: binding requires SMB 3.0+ and the dialect must match.
        let neg_dialect = conn_state
            .negotiate_record
            .lock()
            .await
            .as_ref()
            .map(|r| r.dialect);
        if neg_dialect
            .map(|d| d < DialectConfig::Smb30)
            .unwrap_or(true)
        {
            warn!(
                conn_id = conn_state.conn_id,
                session_id, "binding: requires SMB 3.0+"
            );
            return error_response_for(Command::SessionSetup, NtStatus::NotSupported, &req.header);
        }

        // Add this connection as a channel of the existing session.
        {
            let mut channels = shared.channels.write().unwrap();
            channels.insert(conn_state.conn_id);
        }

        // Swap the ConnState's shared state to point to the existing session's
        // shared state, so this channel sees the same trees/opens/signing/encryption.
        *conn_state.session_shared.write().unwrap() = Some(shared.clone());
        *conn_state.active.write().unwrap() = SessionArcs {
            trees: shared.trees.clone(),
            opens: shared.opens.clone(),
            signing: shared.signing.clone(),
            encryption: shared.encryption.clone(),
            next_tree_id: shared.next_tree_id.clone(),
            next_volatile_id: shared.next_volatile_id.clone(),
            persistent_base: shared.persistent_base,
        };

        // Also add the session to this connection's session list.
        if let Some(session) = existing_session {
            conn_state.sessions.write().await.push(session);
        } else {
            // The session exists in the global registry but not on this connection.
            // Find it in ServerState.sessions.
            let sessions = state.sessions.read().await;
            if let Some(s) = sessions.iter().find(|s| s.id == session_id).cloned() {
                conn_state.sessions.write().await.push(s);
            }
        }

        info!(
            conn_id = conn_state.conn_id,
            session_id, "multichannel: channel bound to existing session"
        );

        // Return a successful SESSION_SETUP response with the session flags
        // from the existing session. The auth token is empty for binding.
        let session_flags = {
            let sessions = conn_state.sessions.read().await;
            sessions
                .iter()
                .find(|s| s.id == session_id)
                .map(|s| {
                    let mut flags = rssmb_proto::session_setup::SessionFlags::new();
                    if s.is_guest {
                        flags.set_is_guest(true);
                    }
                    if s.session_key.as_ref().map(|k| k.is_empty()).unwrap_or(true) {
                        flags.set_is_null_session(true);
                    }
                    // Check encrypt_data from encryption state.
                    let enc = conn_state.encryption_ref();
                    let enc = enc.read().unwrap();
                    if let Some(st) = enc.get(&session_id) {
                        if st.encrypt_data {
                            flags.set_encrypt_data(true);
                        }
                    }
                    flags
                })
                .unwrap_or_default()
        };

        let resp = rssmb_proto::session_setup::SessionSetupResponse {
            session_flags,
            buffer: vec![],
        };
        let mut response = build_response(&req.header, ResponseContent::SessionSetup(resp));
        response.header.session_id = session_id;
        return FramedResponse::Plain(response);
    } else {
        // Re-authentication of an established session and multichannel
        // binding are not supported — refuse instead of pretending success.
        let established = conn_state
            .sessions
            .read()
            .await
            .iter()
            .any(|s| s.id == req.header.session_id);
        debug!(
            conn_id = conn_state.conn_id,
            session_id = req.header.session_id,
            established,
            "session_setup: not a pending SessionId"
        );
        let status = if established {
            NtStatus::NotSupported
        } else {
            NtStatus::UserSessionDeleted
        };
        return error_response_for(Command::SessionSetup, status, &req.header);
    };

    // SMB 3.1.1: hash the SESSION_SETUP request into the session's preauth hash.
    {
        let is_311 = conn_state
            .negotiate_record
            .lock()
            .await
            .as_ref()
            .map(|r| r.dialect == DialectConfig::Smb311)
            .unwrap_or(false);
        if is_311 {
            if let Some(h) = conn_state
                .preauth_sessions
                .lock()
                .unwrap()
                .get_mut(&session_id)
            {
                *h = crate::crypto::preauth_update(h, raw_msg);
            }
        }
    }

    let step = provider.step(input_token, auth_state).await;
    let uses_spnego = auth_state.uses_spnego();
    match step {
        Ok(rssmb_auth::AuthStep::Continue { output_token }) => {
            // Build session setup response with STATUS_MORE_PROCESSING_REQUIRED
            let session_setup_resp = rssmb_proto::session_setup::SessionSetupResponse {
                session_flags: rssmb_proto::session_setup::SessionFlags::new(),
                buffer: output_token,
            };

            let mut response = build_response(
                &req.header,
                ResponseContent::SessionSetup(session_setup_resp),
            );
            response.header.status = NtStatus::MoreProcessingRequired.to_u32();
            response.header.session_id = session_id;
            // SMB 3.1.1: hash the MORE_PROCESSING response into the session's
            // preauth hash (done in the connection loop after encode+sign).
            {
                let is_311 = conn_state
                    .negotiate_record
                    .lock()
                    .await
                    .as_ref()
                    .map(|r| r.dialect == DialectConfig::Smb311)
                    .unwrap_or(false);
                if is_311 {
                    *conn_state.preauth_hash_response.lock().unwrap() =
                        Some(PreauthTarget::Session(session_id));
                }
            }
            FramedResponse::Plain(response)
        }
        Ok(rssmb_auth::AuthStep::Complete {
            output_token,
            session_key,
            identity,
        }) => {
            // Authentication finished. Keep the per-connection auth state
            // alive: Samba/Windows SPNEGO clients send one more round after
            // accept-completed (their mechListMIC for us to verify), and
            // the auth provider handles it as a repeat Complete.
            // *auth_guard is NOT cleared here.

            // Check if a session with this ID already exists (SPNEGO final
            // mic-exchange round).
            let sessions = conn_state.sessions.read().await;
            let existing = sessions.iter().find(|s| s.id == session_id).cloned();
            drop(sessions);

            // Set by the new-session path if the session was admitted with
            // encrypt_data. The SPNEGO mic-exchange path returns early above
            // (the session already exists; its flag was set on first setup).
            // Initialized to false; the new-session path may overwrite it.
            #[allow(unused_assignments)]
            let mut session_encrypt_data = false;

            if existing.is_some() {
                // SPNEGO mic-exchange round: the session was already created
                // on the previous Complete. The client is sending its
                // mechListMIC; just return success with an empty token.
                tracing::debug!(
                    conn_id = conn_state.conn_id,
                    session_id,
                    "session_setup: SPNEGO mic-exchange round — session already established"
                );
                // Clear auth state now — the conversation is truly over.
                *auth_guard = None;
                conn_state
                    .pending_sessions
                    .write()
                    .await
                    .remove(&session_id);

                let resp_token = if !output_token.is_empty() {
                    output_token
                } else if !uses_spnego {
                    vec![]
                } else {
                    vec![0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00]
                };
                let session_flags = if session_key.is_empty() {
                    rssmb_proto::session_setup::SessionFlags::new().with_is_null_session(true)
                } else if identity.is_guest {
                    rssmb_proto::session_setup::SessionFlags::new().with_is_guest(true)
                } else {
                    rssmb_proto::session_setup::SessionFlags::new()
                };
                let session_setup_resp = rssmb_proto::session_setup::SessionSetupResponse {
                    session_flags,
                    buffer: resp_token,
                };
                let mut response = build_response(
                    &req.header,
                    ResponseContent::SessionSetup(session_setup_resp),
                );
                response.header.session_id = session_id;
                return FramedResponse::Plain(response);
            } else {
                // New session: create and populate with auth result.
                // Read the negotiated dialect from the connection's
                // negotiation record. The negotiate gate in handle_plain
                // guarantees this is Some, so disconnect if it's missing
                // (should never happen under normal flow).
                let dialect = {
                    let rec = conn_state.negotiate_record.lock().await;
                    match &*rec {
                        Some(r) => r.dialect,
                        None => {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "SESSION_SETUP without negotiation — disconnecting"
                            );
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::InvalidParameter,
                                &req.header,
                            );
                        }
                    }
                };
                let mut session = Session::new(conn_state.conn_id, session_id);
                session.user_identity = Some(identity.clone());
                session.is_guest = identity.is_guest;
                session.session_key = Some(session_key.clone());
                session.dialect = Some(dialect);

                // --- Transactional admission (MS-SMB2 3.3.5.5.3) ---
                //
                // Derive all keys and run all deny checks BEFORE inserting any
                // per-session state (signing, encryption, session list, preauth).
                // A denial leaves the connection reusable with no orphaned state.

                // MS-SMB2 3.3.5.5.3: an authenticated (non-guest, keyed)
                // session is signed if either side requires it. Guest and
                // anonymous sessions are never signed.
                let signable = !identity.is_guest && !session_key.is_empty();

                // For 3.1.1, the signing key uses the preauth integrity hash
                // as the KDF context. For 3.0.x/2.x, use the legacy fixed
                // context strings.
                let preauth_hash = if dialect == DialectConfig::Smb311 {
                    conn_state
                        .preauth_sessions
                        .lock()
                        .unwrap()
                        .get(&session_id)
                        .copied()
                } else {
                    None
                };
                let (ctx, force_sign_once) = match preauth_hash {
                    Some(ref h) => (crate::crypto::KdfContext::Preauth(h), true),
                    None => {
                        if dialect == DialectConfig::Smb311 {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "3.1.1 session without preauth hash — aborting session"
                            );
                            // Missing preauth hash for 3.1.1 is a fatal error —
                            // don't install signing state with an empty/legacy key.
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                        (crate::crypto::KdfContext::Legacy, false)
                    }
                };

                // --- Cipher selection (MS-SMB2 3.3.5.4 / 3.3.5.5.3) ---
                // Only signable (non-guest, keyed) sessions are eligible for
                // encryption. Guest/anonymous sessions (empty session key) are
                // never encrypted — Samba forces cipher = NONE for them.
                let (neg_cipher, accept_transport_security) = {
                    let rec = conn_state.negotiate_record.lock().await;
                    let neg311 = rec.as_ref().and_then(|r| r.neg311.as_ref());
                    (
                        neg311.and_then(|n| n.cipher),
                        neg311.map(|n| n.accept_transport_security).unwrap_or(false),
                    )
                };
                let cipher: Option<crate::crypto::Cipher> = if signable
                    && dialect >= DialectConfig::Smb30
                {
                    if dialect == DialectConfig::Smb311 {
                        neg_cipher.and_then(|c| match c {
                            EncryptionCipher::Aes128Gcm => Some(crate::crypto::Cipher::Aes128Gcm),
                            _ => None, // CCM not implemented; AES-256 deferred
                        })
                    } else {
                        None // 3.0.x needs CCM (deferred)
                    }
                } else {
                    None
                };

                // MS-SMB2 3.3.5.5.3: if encryption is required and the session
                // cannot be encrypted (no cipher — includes guest, anonymous,
                // 2.x dialect, no common cipher) and Connection.AcceptTransportSecurity
                // is false, deny session establishment.
                // This check runs OUTSIDE `signable` so guest/anon are denied
                // unless transport-level security was accepted (and signable).
                if state.config.encryption == crate::config::EncryptionPolicy::Required
                    && cipher.is_none()
                    && !(accept_transport_security && signable)
                {
                    warn!(conn_id = conn_state.conn_id,
                        dialect = ?dialect, is_guest = identity.is_guest,
                        "encryption required but no cipher available — denying session");
                    return error_response_for(
                        Command::SessionSetup,
                        NtStatus::AccessDenied,
                        &req.header,
                    );
                }

                // Derive signing key (only for signable sessions).
                let signing_key_derived: Option<(Vec<u8>, bool)> = if signable {
                    let key = match crate::crypto::compute_signing_key(&session_key, dialect, ctx) {
                        Ok(k) => k,
                        Err(e) => {
                            warn!(conn_id = conn_state.conn_id, error = %e,
                                "KDF key derivation failed — aborting session");
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let required = state.config.signing == crate::config::SigningPolicy::Required
                        || session_setup_req.security_mode.signing_required();
                    session.signing_key = Some(key.clone());
                    session.signing_required = required;
                    Some((key, required))
                } else {
                    None
                };

                // Derive encryption keys (only if a cipher was negotiated).
                let enc_state_derived: Option<EncryptionState> = if let Some(cipher) = cipher {
                    let enc_key =
                        match crate::crypto::compute_encryption_key(&session_key, dialect, ctx) {
                            Ok(k) => k,
                            Err(e) => {
                                warn!(conn_id = conn_state.conn_id, error = %e,
                                "encryption key derivation failed — aborting session");
                                return error_response_for(
                                    Command::SessionSetup,
                                    NtStatus::LogonFailure,
                                    &req.header,
                                );
                            }
                        };
                    let dec_key =
                        match crate::crypto::compute_decryption_key(&session_key, dialect, ctx) {
                            Ok(k) => k,
                            Err(e) => {
                                warn!(conn_id = conn_state.conn_id, error = %e,
                                "decryption key derivation failed — aborting session");
                                return error_response_for(
                                    Command::SessionSetup,
                                    NtStatus::LogonFailure,
                                    &req.header,
                                );
                            }
                        };
                    let enc_key_arr: [u8; 16] = match enc_key.as_slice().try_into() {
                        Ok(k) => k,
                        Err(_) => {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "encryption key not 16 bytes (got {}) — aborting session",
                                enc_key.len()
                            );
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let dec_key_arr: [u8; 16] = match dec_key.as_slice().try_into() {
                        Ok(k) => k,
                        Err(_) => {
                            warn!(
                                conn_id = conn_state.conn_id,
                                "decryption key not 16 bytes (got {}) — aborting session",
                                dec_key.len()
                            );
                            return error_response_for(
                                Command::SessionSetup,
                                NtStatus::LogonFailure,
                                &req.header,
                            );
                        }
                    };
                    let encrypt_data = state.config.encryption
                        == crate::config::EncryptionPolicy::Required
                        && !accept_transport_security;
                    Some(EncryptionState {
                        enc_key: enc_key_arr,
                        dec_key: dec_key_arr,
                        nonce_source: std::sync::Arc::new(crate::crypto::NonceSource::new(cipher)),
                        cipher,
                        encrypt_data,
                        retiring: false,
                    })
                } else {
                    None
                };

                // --- Commit: all checks passed, insert state atomically ---
                if let Some((key, required)) = signing_key_derived {
                    // 3.1.1: force-sign the final success response once.
                    // This does NOT set Session.SigningRequired — only the one
                    // response is force-signed, not subsequent requests.
                    conn_state.signing_ref().write().unwrap().insert(
                        session_id,
                        SigningState {
                            key,
                            required,
                            dialect,
                            retiring: false,
                            force_sign_once,
                        },
                    );
                }
                if let Some(ref st) = enc_state_derived {
                    conn_state
                        .encryption_ref()
                        .write()
                        .unwrap()
                        .insert(session_id, st.clone());
                    debug!(conn_id = conn_state.conn_id, session_id, cipher = ?st.cipher,
                        "encryption keys derived for session");
                }
                tracing::debug!(conn_id = conn_state.conn_id, username = %identity.username,
                    is_guest = identity.is_guest, signing = session.signing_required, "session authenticated");
                // Audit: logon success.
                tracing::info!(
                    target: "rssmb::audit",
                    conn_id = conn_state.conn_id,
                    session_id,
                    username = %identity.username,
                    is_guest = identity.is_guest,
                    ip = %conn_state.remote_addr,
                    dialect = ?dialect,
                    signing = session.signing_required,
                    encrypted = enc_state_derived.is_some(),
                    "logon success",
                );
                state
                    .metrics
                    .auth_success_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                conn_state.sessions.write().await.push(Arc::new(session));
                // A fresh session establishment on this id retires any
                // tombstone left by a previous-session teardown (ids are
                // server-assigned and effectively never reused, but prune
                // anyway so the retired set stays tight).
                state.retired_sessions.write().unwrap().remove(&session_id);
                // Register the SessionShared in the global registry so that
                // a binding channel can find and share this session's state.
                if let Some(ss) = conn_state.session_shared.read().unwrap().clone() {
                    *ss.username.write().unwrap() = identity.username.clone();
                    state
                        .session_registry
                        .write()
                        .unwrap()
                        .insert(session_id, ss);
                }
                // SMB 3.1.1: remove the preauth session entry (keys derived).
                conn_state
                    .preauth_sessions
                    .lock()
                    .unwrap()
                    .remove(&session_id);
                // Stash the encrypt_data flag so the response builder can set
                // SESSION_FLAG_ENCRYPT_DATA (the session is now in the list).
                session_encrypt_data = enc_state_derived
                    .as_ref()
                    .map(|st| st.encrypt_data)
                    .unwrap_or(false);

                // PreviousSessionId teardown (MS-SMB2 3.3.5.5; Samba
                // smb2srv_session_close_previous): when the new session
                // authenticates as the SAME user as the session named by
                // PreviousSessionId, the old session is torn down — its
                // trees and opens are closed (durable opens survive,
                // orphaned for reconnect), the session is removed from the
                // global tables, and subsequent requests naming it fail
                // with USER_SESSION_DELETED. A different user's session is
                // left untouched.
                let previous_session_id = session_setup_req.previous_session_id;
                debug!(
                    conn_id = conn_state.conn_id,
                    session_id,
                    previous_session_id,
                    "session_setup complete — PreviousSessionId check"
                );
                if previous_session_id != 0 && previous_session_id != session_id {
                    // Complete the old session's pending CHANGE_NOTIFY ops
                    // with NOTIFY_CLEANUP before tearing it down — the
                    // client is blocked in smb2_notify_recv and expects the
                    // async completion (smb2.notify session-reconnect).
                    {
                        let mut pending = conn_state.pending_async.lock().await;
                        let keys: Vec<u64> = pending
                            .iter()
                            .filter(|(_, op)| {
                                op.command == Command::ChangeNotify
                                    && op.session_id == previous_session_id
                            })
                            .map(|(k, _)| *k)
                            .collect();
                        for key in keys {
                            if let Some(op) = pending.remove(&key) {
                                drop(pending);
                                send_notify_cleanup(conn_state, key, op).await;
                                pending = conn_state.pending_async.lock().await;
                            }
                        }
                    }
                    teardown_previous_session(state, previous_session_id, &identity.username).await;
                }
            }

            // The auth provider builds the final SPNEGO response when it can
            // (including the mechListMIC that Samba/Windows clients require).
            // Only fall back to a minimal accept-completed when the provider
            // returned an empty token (bare NTLMSSP / guest / anonymous).
            let resp_token = if !output_token.is_empty() {
                output_token
            } else if !uses_spnego {
                vec![]
            } else {
                // Minimal SPNEGO negTokenResp: SEQUENCE { [0] ENUMERATED 0 (accept-completed) }
                vec![0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00]
            };

            // Anonymous logins (no session key) must be flagged as null
            // sessions, otherwise the client expects to derive a signing key.
            // Set SESSION_FLAG_ENCRYPT_DATA when the session was admitted with
            // encrypt_data (encryption=required). Per Samba, desired alone
            // does NOT set the flag — it only offers the cipher.
            let session_flags = if session_key.is_empty() {
                rssmb_proto::session_setup::SessionFlags::new().with_is_null_session(true)
            } else if identity.is_guest {
                rssmb_proto::session_setup::SessionFlags::new().with_is_guest(true)
            } else {
                rssmb_proto::session_setup::SessionFlags::new()
            };
            let session_flags = if session_encrypt_data {
                session_flags.with_encrypt_data(true)
            } else {
                session_flags
            };

            let session_setup_resp = rssmb_proto::session_setup::SessionSetupResponse {
                session_flags,
                buffer: resp_token,
            };

            let mut response = build_response(
                &req.header,
                ResponseContent::SessionSetup(session_setup_resp),
            );
            response.header.session_id = session_id;
            FramedResponse::Plain(response)
        }
        Ok(rssmb_auth::AuthStep::Reject { reason }) => {
            debug!(conn_id = conn_state.conn_id, "auth rejected: {}", reason);
            *auth_guard = None; // Clear auth state
            conn_state
                .pending_sessions
                .write()
                .await
                .remove(&session_id);
            conn_state
                .preauth_sessions
                .lock()
                .unwrap()
                .remove(&session_id);
            // Throttle: record failure, apply delay, check per-connection cap.
            // The delay is applied after dropping auth_guard (the lock is no
            // longer needed). The failure is recorded BEFORE the delay so
            // disconnecting during the wait cannot evade accounting.
            // Audit: logon failure.
            tracing::warn!(
                target: "rssmb::audit",
                conn_id = conn_state.conn_id,
                session_id,
                ip = %conn_state.remote_addr,
                reason = %reason,
                "logon failure",
            );
            state
                .metrics
                .auth_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drop(auth_guard);
            let delay = state.auth_limiter.record_failure(conn_state.remote_addr);
            let conn_fails = conn_state
                .auth_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                conn_id = conn_state.conn_id,
                ip = %conn_state.remote_addr,
                reason = %reason,
                delay_ms = delay.as_millis() as u64,
                conn_failures = conn_fails,
                "auth failure",
            );
            if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                warn!(
                    conn_id = conn_state.conn_id,
                    conn_failures = conn_fails,
                    "per-connection auth failure cap exceeded — disconnecting"
                );
                return FramedResponse::Disconnect;
            }
            if !delay.is_zero() {
                tokio::select! {
                    biased;
                    _ = state.shutdown.notified() => {
                        debug!(conn_id = conn_state.conn_id, "shutdown during auth delay");
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            error_response_for(Command::SessionSetup, NtStatus::LogonFailure, &req.header)
        }
        Err(e) => {
            debug!(conn_id = conn_state.conn_id, "auth error: {}", e);
            *auth_guard = None;
            conn_state
                .pending_sessions
                .write()
                .await
                .remove(&session_id);
            conn_state
                .preauth_sessions
                .lock()
                .unwrap()
                .remove(&session_id);
            drop(auth_guard);
            let delay = state.auth_limiter.record_failure(conn_state.remote_addr);
            let conn_fails = conn_state
                .auth_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                conn_id = conn_state.conn_id,
                ip = %conn_state.remote_addr,
                error = %e,
                delay_ms = delay.as_millis() as u64,
                conn_failures = conn_fails,
                "auth error (throttled)",
            );
            if state.auth_limiter.conn_failure_exceeds(conn_fails) {
                warn!(
                    conn_id = conn_state.conn_id,
                    conn_failures = conn_fails,
                    "per-connection auth failure cap exceeded — disconnecting"
                );
                return FramedResponse::Disconnect;
            }
            if !delay.is_zero() {
                tokio::select! {
                    biased;
                    _ = state.shutdown.notified() => {
                        debug!(conn_id = conn_state.conn_id, "shutdown during auth delay");
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            error_response_for(Command::SessionSetup, NtStatus::LogonFailure, &req.header)
        }
    }
}
