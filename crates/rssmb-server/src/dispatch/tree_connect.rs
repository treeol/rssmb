use super::*;

pub(crate) async fn handle_tree_connect(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let tc_req = match &req.content {
        RequestContent::TreeConnect(tc) => tc,
        _ => {
            return error_response_for(
                Command::TreeConnect,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    // Look up the session to enforce share access policy.
    let session_id = req.header.session_id;
    let session_identity = {
        let sessions = conn_state.sessions.read().await;
        sessions
            .iter()
            .find(|s| s.id == session_id)
            .and_then(|s| s.user_identity.clone())
    };

    // If no session identity was found, reject — only NEGOTIATE and
    // SESSION_SETUP may proceed without an authenticated session.
    let identity = match session_identity {
        Some(id) => id,
        None => {
            debug!(
                conn_id = conn_state.conn_id,
                session_id, "tree_connect: no authenticated session"
            );
            return error_response_for(
                Command::TreeConnect,
                NtStatus::UserSessionDeleted,
                &req.header,
            );
        }
    };

    // Extract share name from the path (format: \\server\share)
    let path = tc_req.buffer.to_string();
    let share_name = extract_share_name(&path);

    // IPC$ — the inter-process share clients use for share enumeration (SrvSvc).
    // Accept the connect as a pipe share so clients don't abort; the RPC layer
    // behind it is still a stub.
    if share_name.eq_ignore_ascii_case("IPC$") {
        let tree_id = next_tree_id(conn_state);
        conn_state.trees_ref().write().await.insert(
            tree_id,
            TreeEntry {
                share_name: "IPC$".to_string(),
                vfs: Arc::new(rssmb_vfs::memoryfs::MemoryFs::new()) as Arc<dyn rssmb_vfs::Vfs>,
                session_id,
                read_only: false,
                write_access: true,
                encrypt_data: false,
                is_ipc: true,
            },
        );
        let resp = rssmb_proto::tree_connect::TreeConnectResponse {
            share_type: rssmb_proto::tree_connect::ShareType::Pipe,
            maximal_access: 0x001f_01ff,
            ..Default::default()
        };
        let mut response = build_response(&req.header, ResponseContent::TreeConnect(resp));
        response.header.tree_id = Some(tree_id);
        return FramedResponse::Plain(response);
    }

    // Look up share in the live shares snapshot (case-insensitive).
    let live_shares = state.shares_snapshot();
    let share_config = match live_shares
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&share_name))
        .map(|(_, v)| v)
    {
        Some(c) => c.clone(),
        None => {
            debug!(conn_id = conn_state.conn_id, share = %share_name, "share not found");
            return error_response_for(
                Command::TreeConnect,
                NtStatus::ObjectNameNotFound,
                &req.header,
            );
        }
    };

    // ── Share access policy ─────────────────────────────────────────────
    // 1. Guest users can only connect if the share allows guest access.
    // 2. If valid_users is non-empty, the user must be in the list
    //    (guests are also subject to this check if valid_users is set).
    // 3. If read_users is non-empty, the user must be in the list to
    //    get any access (read or write).
    // 4. If write_users is non-empty, only users in the list get write
    //    access; others get read-only access on a read-write share.
    // 5. MaximalAccess reflects read_only and write_access policy.
    if identity.is_guest && !share_config.guest_ok {
        debug!(conn_id = conn_state.conn_id, share = %share_name, "guest denied on non-guest share");
        return error_response_for(Command::TreeConnect, NtStatus::AccessDenied, &req.header);
    }

    if !share_config.valid_users.is_empty() {
        let user_allowed = share_config
            .valid_users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&identity.username));
        if !user_allowed {
            debug!(conn_id = conn_state.conn_id, share = %share_name, user = %identity.username, "user not in valid_users");
            return error_response_for(Command::TreeConnect, NtStatus::AccessDenied, &req.header);
        }
    }

    if !share_config.read_users.is_empty() {
        let user_can_read = share_config
            .read_users
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&identity.username));
        if !user_can_read {
            debug!(conn_id = conn_state.conn_id, share = %share_name, user = %identity.username, "user not in read_users");
            return error_response_for(Command::TreeConnect, NtStatus::AccessDenied, &req.header);
        }
    }

    // Determine write access: read_only share → no write. Otherwise,
    // write_users non-empty → only listed users get write. Empty
    // write_users → all users with access get write.
    let write_access = !share_config.read_only && {
        if share_config.write_users.is_empty() {
            true
        } else {
            share_config
                .write_users
                .iter()
                .any(|u| u.eq_ignore_ascii_case(&identity.username))
        }
    };

    // Derive MaximalAccess from access policy.
    // Read-only or no-write-access: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE = 0x001200a9
    // Full read-write: FILE_ALL_ACCESS = 0x001f01ff
    let maximal_access = if write_access {
        0x001f_01ff
    } else {
        0x0012_00a9
    };

    // Create VFS backend: LocalFs for real shares, MemoryFs for unnamed/test.
    // publish_on_close selects the LocalFs variant with the hidden-temp/
    // atomic-rename backend (see rssmb_vfs::publish).
    let vfs: Arc<dyn rssmb_vfs::Vfs> = if share_config.path.is_empty() {
        Arc::new(rssmb_vfs::memoryfs::MemoryFs::new())
    } else if share_config.publish_on_close {
        match rssmb_vfs::localfs::LocalFs::new_with_publish(
            &share_config.path,
            share_config.follow_symlinks,
            share_config.case_sensitive,
        ) {
            Ok(fs) => Arc::new(fs),
            Err(e) => {
                tracing::warn!(share = %share_name, path = share_config.path, error = %e, "failed to create LocalFs");
                return error_response_for(
                    Command::TreeConnect,
                    NtStatus::InvalidParameter,
                    &req.header,
                );
            }
        }
    } else {
        match rssmb_vfs::localfs::LocalFs::new(
            &share_config.path,
            share_config.follow_symlinks,
            share_config.case_sensitive,
        ) {
            Ok(fs) => Arc::new(fs),
            Err(e) => {
                tracing::warn!(share = %share_name, path = %share_config.path, error = %e, "failed to create LocalFs");
                return error_response_for(
                    Command::TreeConnect,
                    NtStatus::InvalidParameter,
                    &req.header,
                );
            }
        }
    };

    // Assign tree ID
    let tree_id = next_tree_id(conn_state);

    // Store tree in connection tree table with owning session and policy.
    // MS-SMB2 3.3.5.7: if Connection.AcceptTransportSecurity is true, do not
    // require SMB-layer encryption on the tree.
    let accept_transport_security = conn_state
        .negotiate_record
        .lock()
        .await
        .as_ref()
        .and_then(|r| r.neg311.as_ref())
        .map(|n| n.accept_transport_security)
        .unwrap_or(false);
    let tree_encrypt_data = share_config.encrypt_data && !accept_transport_security;
    conn_state.trees_ref().write().await.insert(
        tree_id,
        TreeEntry {
            share_name: share_name.clone(),
            vfs: vfs.clone(),
            session_id,
            read_only: share_config.read_only,
            write_access,
            encrypt_data: tree_encrypt_data,
            is_ipc: false,
        },
    );

    // Audit: tree connect.
    tracing::info!(
        target: "rssmb::audit",
        conn_id = conn_state.conn_id,
        session_id,
        tree_id,
        share = %share_name,
        username = %identity.username,
        ip = %conn_state.remote_addr,
        read_only = share_config.read_only,
        write_access,
        "tree connect",
    );

    let tree_connect_response = rssmb_proto::tree_connect::TreeConnectResponse {
        share_type: rssmb_proto::tree_connect::ShareType::Disk,
        share_flags: rssmb_proto::tree_connect::ShareFlags::new()
            .with_encrypt_data(tree_encrypt_data),
        maximal_access,
        ..Default::default()
    };

    let mut response = build_response(
        &req.header,
        ResponseContent::TreeConnect(tree_connect_response),
    );
    response.header.tree_id = Some(tree_id);
    FramedResponse::Plain(response)
}
