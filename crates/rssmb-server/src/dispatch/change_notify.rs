use super::*;

pub(crate) async fn handle_change_notify(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let cn_req = match &req.content {
        RequestContent::ChangeNotify(cn) => cn,
        _ => {
            return error_response_for(
                Command::ChangeNotify,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    let file_id_volatile = cn_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Validate the handle belongs to this session.
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::ChangeNotify, status, &req.header),
        };

    // CHANGE_NOTIFY requires a directory handle.
    if !entry.is_pipe {
        let info = entry
            .vfs
            .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
            .await
            .unwrap_or(rssmb_vfs::FileInfo {
                file_id: rssmb_vfs::FileId { dev: 0, ino: 0 },
                attributes: rssmb_vfs::FileAttributes::default(),
                size: 0,
                allocation_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                file_name: String::new(),
            });
        if !info.attributes.directory {
            debug!(
                conn_id = conn_state.conn_id,
                "change_notify: handle is not a directory"
            );
            return error_response_for(
                Command::ChangeNotify,
                NtStatus::InvalidParameter,
                &req.header,
            );
        }
    }

    let message_id = req.header.message_id;
    let watch_tree = cn_req.flags.watch_tree();

    // Build the CompletionFilter from the request.
    let filter = crate::notify::CompletionFilter {
        file_name: cn_req.completion_filter.file_name(),
        dir_name: cn_req.completion_filter.dir_name(),
        attributes: cn_req.completion_filter.attributes(),
        size: cn_req.completion_filter.size(),
        last_write: cn_req.completion_filter.last_write(),
        last_access: cn_req.completion_filter.last_access(),
        creation: cn_req.completion_filter.creation(),
        ea: cn_req.completion_filter.ea(),
        security: cn_req.completion_filter.security(),
        stream_name: cn_req.completion_filter.stream_name(),
        stream_size: cn_req.completion_filter.stream_size(),
        stream_write: cn_req.completion_filter.stream_write(),
    };

    // Start the directory watch. The path is the share root joined with
    // the handle's relative path. For the share root itself (entry.path
    // is ""), the watch is on the share root.
    // We use the share root path from the VFS — but we don't have access
    // to the actual filesystem path from the VFS trait. The notify
    // watcher needs a real filesystem path, so we reconstruct it from
    // the share config path + the entry's relative path.
    let dir_path = {
        let trees_ref = conn_state.trees_ref();
        let trees = trees_ref.read().await;
        let share_name = trees
            .get(&tree_id)
            .map(|t| t.share_name.clone())
            .unwrap_or_default();
        // Look up the share path from config.
        let share_path = state
            .shares_snapshot()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&share_name))
            .map(|(_, v)| v.path.clone())
            .unwrap_or_default();
        if share_path.is_empty() {
            debug!(
                conn_id = conn_state.conn_id,
                "change_notify: no share path — using stub"
            );
            // No real path — fall back to the stub (no real watching).
            let (cancel_tx, _cancel_rx) = tokio::sync::oneshot::channel::<()>();
            conn_state.pending_async.lock().await.insert(
                message_id,
                AsyncOp {
                    command: Command::ChangeNotify,
                    session_id,
                    tree_id,
                    cancel: cancel_tx,
                    notify_handle: None,
                    watched_file_id: None,
                    lock_open_volatile: None,
                },
            );
            let mut response = build_response(
                &req.header,
                ResponseContent::ChangeNotify(rssmb_proto::notify::ChangeNotifyResponse {
                    buffer: Default::default(),
                }),
            );
            response.header.status = NtStatus::Pending.to_u32();
            response.header.to_async(message_id);
            return FramedResponse::Plain(response);
        }
        // Join the share path with the entry's relative path.
        let mut path = std::path::PathBuf::from(share_path);
        if !entry.path.is_empty() {
            // The entry path is share-relative (e.g. "subdir/file.txt").
            // Join it with the share root.
            path.push(&entry.path);
        }
        path
    };

    // Register the async op before starting the watcher task so an immediate
    // watcher failure or quick event can remove it cleanly from pending_async.
    let max_output_length = cn_req.output_buffer_length;
    let mut pending_guard = conn_state.pending_async.lock().await;
    let notify_handle = crate::notify::start_watch(
        conn_state,
        message_id,
        session_id,
        tree_id,
        dir_path,
        watch_tree,
        filter,
        max_output_length,
    );
    let (cancel_tx, _cancel_rx) = tokio::sync::oneshot::channel::<()>();
    pending_guard.insert(
        message_id,
        AsyncOp {
            command: Command::ChangeNotify,
            session_id,
            tree_id,
            cancel: cancel_tx,
            notify_handle: Some(notify_handle),
            watched_file_id: Some(file_id_volatile),
            lock_open_volatile: None,
        },
    );
    drop(pending_guard);

    // Build a PENDING response with async header.
    let mut response = build_response(
        &req.header,
        ResponseContent::ChangeNotify(rssmb_proto::notify::ChangeNotifyResponse {
            buffer: Default::default(),
        }),
    );
    response.header.status = NtStatus::Pending.to_u32();
    response.header.to_async(message_id);
    FramedResponse::Plain(response)
}
