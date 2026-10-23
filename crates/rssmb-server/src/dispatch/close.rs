use super::*;

pub(crate) async fn handle_close(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let close_req = match &req.content {
        RequestContent::Close(c) => c,
        _ => return error_response_for(Command::Close, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = close_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // Look up and remove the open, validating session ownership.
    let open_entry = {
        let opens_ref = conn_state.opens_ref();
        let mut opens = opens_ref.write().await;
        match opens.get(&file_id_volatile) {
            Some(entry) => {
                if entry.session_id != session_id || entry.tree_id != tree_id {
                    debug!(
                        conn_id = conn_state.conn_id,
                        file_id = file_id_volatile,
                        "close: handle does not belong to this session/tree"
                    );
                    return error_response_for(
                        Command::Close,
                        NtStatus::InvalidHandle,
                        &req.header,
                    );
                }
                opens.remove(&file_id_volatile)
            }
            None => None,
        }
    };
    match open_entry {
        Some(entry) => {
            // If the client set POSTQUERY_ATTRIB, query the VFS for file
            // metadata before closing so we can return it in the response.
            let postquery = close_req.flags.postquery_attrib();

            let (
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                allocation_size,
                endof_file,
                file_attributes,
            ) = if postquery {
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
                (
                    FileTime::from(info.creation_time),
                    FileTime::from(info.last_access_time),
                    FileTime::from(info.last_write_time),
                    FileTime::from(info.change_time),
                    info.allocation_size,
                    info.size,
                    Default::default(),
                )
            } else {
                (
                    FileTime::ZERO,
                    FileTime::ZERO,
                    FileTime::ZERO,
                    FileTime::ZERO,
                    0,
                    0,
                    Default::default(),
                )
            };

            // Close via VFS (skip for pipe opens — no VFS handle).
            // For disk opens, remove from the global open table first.
            // The OpenTable tracks delete_on_close per-open. remove()
            // returns any_delete_on_close = true if the file's
            // delete_pending disposition was set (by this open or a
            // previously-closed one). When this is the last open,
            // was_last=true and any_delete_on_close=true → the file
            // must be unlinked. The VFS close() unlinks if the handle's
            // delete_on_close flag is set; for DOC set via SET_INFO
            // (not at create time), vfs.delete() is called instead.
            if !entry.is_pipe {
                // Remove from the global open table and check if this was
                // the last open with delete-on-close pending.
                if let Some(fid) = entry.file_id {
                    let remove_result = state.open_table.remove(fid, entry.open_id).await;
                    if remove_result.was_last && remove_result.any_delete_on_close {
                        // Last open with delete-pending disposition (possibly set
                        // by an earlier open that has already closed) — ensure
                        // this VFS handle's delete_on_close flag is set before
                        // close() unlinks the file.
                        let _ = entry.vfs.set_delete_on_close(entry.open_id, true).await;
                    }
                    // Release all byte-range locks held by this open.
                    state
                        .open_table
                        .release_all_locks_for_open(entry.open_id)
                        .await;
                }
                state
                    .open_table
                    .remove_open_from_leases(entry.open_id)
                    .await;

                // If this was a durable open, remove it from the durable
                // table. The VFS handle is closed below — `forget` does not
                // close it, avoiding a double-close.
                if let Some(guid) = entry.durable_guid {
                    state.durable_table.forget(&guid).await;
                }
                if let Some(pid) = entry.durable_persistent_id {
                    state.durable_table.forget_v1(pid).await;
                }

                if let Err(e) = entry.vfs.close(entry.open_id).await {
                    debug!(conn_id = conn_state.conn_id, error = %e, "close VFS failed");
                }
            }

            // Complete any pending CHANGE_NOTIFY whose WATCHED HANDLE is
            // the one being closed with STATUS_NOTIFY_CLEANUP
            // (MS-SMB2 3.3.5.10: closes the watch and notifies the client
            // via an async completion). Other pending CHANGE_NOTIFY ops on
            // this tree watch DIFFERENT handles and must stay pending —
            // cancelling them tree-wide hung smb2.notify's valid-req
            // (setup-file CLOSE killed the unrelated root-dir watch).
            {
                let mut pending = conn_state.pending_async.lock().await;
                let closed_volatile = file_id_volatile;
                let cleanup_keys: Vec<u64> = pending
                    .iter()
                    .filter(|(_, op)| {
                        op.command == Command::ChangeNotify
                            && op.tree_id == tree_id
                            && op.watched_file_id == Some(closed_volatile)
                    })
                    .map(|(k, _)| *k)
                    .collect();
                for key in cleanup_keys {
                    if let Some(op) = pending.remove(&key) {
                        // Guard must be released first — send_notify_cleanup
                        // awaits, and re-locking below while the old guard
                        // is still held would self-deadlock the connection
                        // task (Rust drops the old binding only AFTER the
                        // RHS completes).
                        drop(pending);
                        // Stops the watcher, then sends the async
                        // NOTIFY_CLEANUP completion.
                        send_notify_cleanup(conn_state, key, op).await;
                        // Re-acquire for any remaining keys.
                        pending = conn_state.pending_async.lock().await;
                    }
                }
                // Pended blocking LOCKs owned by the CLOSING open are
                // completed with RANGE_NOT_LOCKED (torture cancel "cancel
                // by close", lock.c:978 — the client's smb2_lock_recv must
                // unblock when h2 closes). Locks pended by other opens are
                // untouched.
                let lock_keys: Vec<u64> = pending
                    .iter()
                    .filter(|(_, op)| {
                        op.command == Command::Lock
                            && op.lock_open_volatile == Some(closed_volatile)
                            && op.session_id == session_id
                    })
                    .map(|(k, _)| *k)
                    .collect();
                for key in lock_keys {
                    if let Some(op) = pending.remove(&key) {
                        drop(pending);
                        let mut header = Header {
                            credit_charge: 0,
                            status: NtStatus::RangeNotLocked.to_u32(),
                            command: Command::Lock,
                            credit_request: 0,
                            flags: HeaderFlags::new().with_server_to_redir(true),
                            next_command: 0,
                            message_id: key,
                            tree_id: Some(op.tree_id),
                            async_id: None,
                            session_id: op.session_id,
                            signature: 0,
                        };
                        header.to_async(key);
                        let resp = FramedResponse::Plain(PlainResponse {
                            header,
                            content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                                error_data: vec![],
                            }),
                        });
                        send_unsolicited(conn_state, &resp, true).await;
                        pending = conn_state.pending_async.lock().await;
                    }
                }
            }

            let close_flags = if postquery {
                rssmb_proto::create::CloseFlags::new().with_postquery_attrib(true)
            } else {
                rssmb_proto::create::CloseFlags::new()
            };

            let close_response = rssmb_proto::create::CloseResponse {
                flags: close_flags,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                allocation_size,
                endof_file,
                file_attributes,
            };
            let response = build_response(&req.header, ResponseContent::Close(close_response));
            FramedResponse::Plain(response)
        }
        None => {
            debug!(
                conn_id = conn_state.conn_id,
                file_id = file_id_volatile,
                "close: handle not found"
            );
            // Close of an unknown/already-closed handle is FILE_CLOSED
            // (MS-SMB2 3.3.5.16: fail with STATUS_FILE_CLOSED; torture
            // connect.c:227 asserts exactly this on double-close).
            error_response_for(Command::Close, NtStatus::FileClosed, &req.header)
        }
    }
}
