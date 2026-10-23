use super::*;

pub(crate) async fn handle_set_info(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let si_req = match &req.content {
        RequestContent::SetInfo(s) => s,
        _ => return error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header),
    };

    let file_id_volatile = si_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::SetInfo, status, &req.header),
        };

    // Pipe opens don't support SET_INFO.
    if entry.is_pipe {
        return error_response_for(Command::SetInfo, NtStatus::Other(0xC000_0010), &req.header);
    }

    // Only File-type SET_INFO is supported for now.
    // InfoType::File = 0x01 is the only supported type for SET_INFO.
    // InfoType::Security (0x03) is accepted and ignored (the SD is not
    // persisted — documented as unsupported in the README/plan).
    let is_file_type = si_req.info_type == InfoType::File;
    let is_security_type = si_req.info_type == InfoType::Security;
    if !is_file_type && !is_security_type {
        return error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header);
    }
    if is_security_type {
        // Security SET_INFO: accept and succeed without persisting.
        // This is a documented compatibility behavior — the SD is not
        // mapped back to POSIX mode bits. A strict mode would return
        // ACCESS_DENIED here.
        debug!(
            conn_id = conn_state.conn_id,
            "set_info security: accepted (not persisted)"
        );
        return FramedResponse::Plain(build_response(
            &req.header,
            ResponseContent::SetInfo(rssmb_proto::info::SetInfoResponse::default()),
        ));
    }

    // Get the info class and raw data.
    let class_byte = si_req.info_class.0;
    let raw_data = si_req.data.data().to_vec();

    // Every handled file SET_INFO class mutates (timestamps, size, rename,
    // delete). On a read-only share or for a user without write access,
    // refuse them all — except clearing delete-pending, which is harmless
    // but also pointless, so refuse too.
    if tree_read_only(conn_state, tree_id).await || !tree_write_access(conn_state, tree_id).await {
        return error_response_for(Command::SetInfo, NtStatus::AccessDenied, &req.header);
    }

    // Parse and apply the specific info class.
    use binrw::BinRead;
    match class_byte {
        // FileBasicInformation (4): set timestamps and attributes
        4 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileBasicInformation::read_le(&mut cursor) {
                Ok(basic) => {
                    // Query current info, apply changes, call set_info.
                    let mut info = match entry
                        .vfs
                        .query_info(entry.open_id, rssmb_vfs::InfoClass::FileBasicInfo)
                        .await
                    {
                        Ok(i) => i,
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info: query failed");
                            return error_response_for(
                                Command::SetInfo,
                                NtStatus::InvalidParameter,
                                &req.header,
                            );
                        }
                    };
                    // Apply timestamps (0 means "don't change" in MS-FSCC).
                    // FileTime is stored as u64; 0 means don't change.
                    if basic.creation_time.as_u64() != 0 {
                        info.creation_time = basic.creation_time.as_u64();
                    }
                    if basic.last_access_time.as_u64() != 0 {
                        info.last_access_time = basic.last_access_time.as_u64();
                    }
                    if basic.last_write_time.as_u64() != 0 {
                        info.last_write_time = basic.last_write_time.as_u64();
                    }
                    if basic.change_time.as_u64() != 0 {
                        info.change_time = basic.change_time.as_u64();
                    }
                    // Apply DOS attributes (READONLY, HIDDEN, SYSTEM, ARCHIVE).
                    // The VFS set_info maps READONLY to the owner write bit.
                    // HIDDEN/SYSTEM/ARCHIVE are accepted but not yet persisted
                    // in xattr (Phase 2.8 partial — READONLY only).
                    info.attributes.read_only = basic.file_attributes.readonly();
                    info.attributes.hidden = basic.file_attributes.hidden();
                    info.attributes.system = basic.file_attributes.system();
                    info.attributes.archive = basic.file_attributes.archive();
                    match entry
                        .vfs
                        .set_info(entry.open_id, rssmb_vfs::InfoClass::FileBasicInfo, &info)
                        .await
                    {
                        Ok(()) => {
                            let response = build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            );
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info basic failed");
                            error_response_for(
                                Command::SetInfo,
                                NtStatus::InvalidParameter,
                                &req.header,
                            )
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse basic failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        // FileEndOfFileInformation (20): truncate or extend
        20 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileEndOfFileInformation::read_le(&mut cursor) {
                Ok(eof) => {
                    if let Some(fid) = entry.file_id {
                        let (breaks, waiters) = state
                            .open_table
                            .break_for_op(fid, Some(entry.open_id), opens::ConflictOp::Write)
                            .await;
                        send_break_notifications(&breaks).await;
                        state.open_table.arm_break_timers(&waiters);
                    }
                    let mut info = match entry
                        .vfs
                        .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                        .await
                    {
                        Ok(i) => i,
                        Err(_) => {
                            return error_response_for(
                                Command::SetInfo,
                                NtStatus::InvalidParameter,
                                &req.header,
                            )
                        }
                    };
                    info.size = eof.end_of_file;
                    match entry
                        .vfs
                        .set_info(
                            entry.open_id,
                            rssmb_vfs::InfoClass::FileEndOfFileInfo,
                            &info,
                        )
                        .await
                    {
                        Ok(()) => {
                            let response = build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            );
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_info eof failed");
                            let status = match e {
                                rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                                _ => NtStatus::InvalidParameter,
                            };
                            error_response_for(Command::SetInfo, status, &req.header)
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse eof failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        // FileDispositionInformation (13): mark delete-on-close
        13 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileDispositionInformation::read_le(&mut cursor) {
                Ok(disp) => {
                    let delete_pending = bool::from(disp.delete_pending);
                    debug!(
                        conn_id = conn_state.conn_id,
                        delete_pending, "set_info disposition"
                    );
                    if delete_pending && tree_read_only(conn_state, tree_id).await {
                        return error_response_for(
                            Command::SetInfo,
                            NtStatus::AccessDenied,
                            &req.header,
                        );
                    }
                    if delete_pending {
                        if let Some(fid) = entry.file_id {
                            let (breaks, waiters) = state
                                .open_table
                                .break_for_op(
                                    fid,
                                    Some(entry.open_id),
                                    opens::ConflictOp::HandleOrDelete,
                                )
                                .await;
                            send_break_notifications(&breaks).await;
                            state.open_table.arm_break_timers(&waiters);
                        }
                    }
                    match entry
                        .vfs
                        .set_delete_on_close(entry.open_id, delete_pending)
                        .await
                    {
                        Ok(()) => {
                            // Update the global open table's delete_on_close
                            // flag for this open so that the last-close logic
                            // in handle_close knows whether to unlink.
                            if let Some(fid) = entry.file_id {
                                state
                                    .open_table
                                    .update_delete_on_close(fid, entry.open_id, delete_pending)
                                    .await;
                            }
                            FramedResponse::Plain(build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            ))
                        }
                        Err(rssmb_vfs::VfsError::DirectoryNotEmpty) => error_response_for(
                            Command::SetInfo,
                            NtStatus::DirectoryNotEmpty,
                            &req.header,
                        ),
                        Err(rssmb_vfs::VfsError::AccessDenied) => error_response_for(
                            Command::SetInfo,
                            NtStatus::AccessDenied,
                            &req.header,
                        ),
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "set_delete_on_close failed");
                            error_response_for(
                                Command::SetInfo,
                                NtStatus::NotSupported,
                                &req.header,
                            )
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse disposition failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        // FileRenameInformation (10): rename the file
        10 => {
            let mut cursor = std::io::Cursor::new(&raw_data[..]);
            match rssmb_proto::fscc::FileRenameInformation::read_le(&mut cursor) {
                Ok(rename) => {
                    let new_name = rename.file_name.to_string();
                    let replace = rename.replace_if_exists.into();
                    if let Some(fid) = entry.file_id {
                        // Samba delay_rename_for_lease_break (smb2_setinfo.c):
                        // a rename defers iff another lease on this file holds
                        // Handle caching — the break target is state minus H
                        // (keep R+W), and the rename pends until the holder
                        // acks or the 70 s timeout fires (rename_wait golden).
                        let (breaks, waiters) = state
                            .open_table
                            .break_for_op(fid, Some(entry.open_id), opens::ConflictOp::Rename)
                            .await;
                        send_break_notifications(&breaks).await;
                        state.open_table.arm_break_timers(&waiters);
                        if !waiters.is_empty() {
                            // Rename must pend for the H-removing break.
                            // Return an interim PENDING and spawn a completion
                            // task that awaits the break waiters (with 70 s
                            // cap) then performs the rename.
                            let message_id = req.header.message_id;
                            let session_id = req.header.session_id;
                            let tree_id = req.header.tree_id.unwrap_or(0);
                            let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
                            conn_state.pending_async.lock().await.insert(
                                message_id,
                                AsyncOp {
                                    command: Command::SetInfo,
                                    session_id,
                                    tree_id,
                                    cancel: cancel_tx,
                                    notify_handle: None,
                                    watched_file_id: None,
                                    lock_open_volatile: None,
                                },
                            );
                            // Send interim STATUS_PENDING. Construct manually
                            // (build_response overwrites flags/status).
                            let mut pending_hdr = req.header.clone();
                            pending_hdr.status = NtStatus::Pending.to_u32();
                            pending_hdr.to_async(message_id);
                            pending_hdr.flags = pending_hdr.flags.with_server_to_redir(true);
                            let pending_resp = PlainResponse {
                                header: pending_hdr,
                                content: ResponseContent::Error(
                                    rssmb_proto::error::ErrorResponse { error_data: vec![] },
                                ),
                            };
                            // Spawn completion task.
                            let state_clone = state;
                            let conn_clone = conn_state.clone();
                            let vfs_clone = entry.vfs.clone();
                            let open_id = entry.open_id;
                            let req_header = req.header.clone();
                            let client_signed = req.header.flags.signed();
                            tokio::spawn(async move {
                                let timeout =
                                    tokio::time::sleep(std::time::Duration::from_secs(70));
                                let wait_all = futures::future::join_all(
                                    waiters.into_iter().map(|w| w.receiver),
                                );
                                tokio::pin!(wait_all);
                                tokio::pin!(timeout);
                                tokio::select! {
                                    _ = wait_all => {}
                                    _ = timeout => {}
                                    _ = cancel_rx => {
                                        conn_clone.pending_async.lock().await.remove(&message_id);
                                        return;
                                    }
                                }
                                conn_clone.pending_async.lock().await.remove(&message_id);
                                match vfs_clone.rename(open_id, &new_name, replace).await {
                                    Ok(()) => {
                                        let mut resp = build_response(
                                            &req_header,
                                            ResponseContent::SetInfo(
                                                rssmb_proto::info::SetInfoResponse::default(),
                                            ),
                                        );
                                        resp.header.to_async(message_id);
                                        let framed = FramedResponse::Plain(resp);
                                        send_unsolicited(&conn_clone, &framed, client_signed).await;
                                    }
                                    Err(e) => {
                                        let status = match e {
                                            rssmb_vfs::VfsError::InvalidHandle => {
                                                NtStatus::InvalidHandle
                                            }
                                            rssmb_vfs::VfsError::AlreadyExists => {
                                                NtStatus::ObjectNameCollision
                                            }
                                            rssmb_vfs::VfsError::AccessDenied => {
                                                NtStatus::AccessDenied
                                            }
                                            rssmb_vfs::VfsError::NotFound => {
                                                NtStatus::ObjectNameNotFound
                                            }
                                            rssmb_vfs::VfsError::DirectoryNotEmpty => {
                                                NtStatus::DirectoryNotEmpty
                                            }
                                            rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                                            _ => NtStatus::InvalidParameter,
                                        };
                                        let err_resp = error_response_for(
                                            Command::SetInfo,
                                            status,
                                            &req_header,
                                        );
                                        // Convert to async for the pended response.
                                        let framed = match err_resp {
                                            FramedResponse::Plain(mut p) => {
                                                p.header.to_async(message_id);
                                                FramedResponse::Plain(p)
                                            }
                                            other => other,
                                        };
                                        send_unsolicited(&conn_clone, &framed, client_signed).await;
                                    }
                                }
                                let _ = state_clone; // keep alive
                            });
                            // Return the interim PENDING response; the
                            // completion is sent out-of-band.
                            return FramedResponse::Plain(pending_resp);
                        }
                    }
                    debug!(conn_id = conn_state.conn_id, new_name = %new_name, "set_info rename");
                    match entry
                        .vfs
                        .rename(entry.open_id, &new_name, rename.replace_if_exists.into())
                        .await
                    {
                        Ok(()) => {
                            let response = build_response(
                                &req.header,
                                ResponseContent::SetInfo(
                                    rssmb_proto::info::SetInfoResponse::default(),
                                ),
                            );
                            FramedResponse::Plain(response)
                        }
                        Err(e) => {
                            debug!(conn_id = conn_state.conn_id, error = %e, "rename failed");
                            let status = match e {
                                rssmb_vfs::VfsError::InvalidHandle => NtStatus::InvalidHandle,
                                rssmb_vfs::VfsError::AlreadyExists => NtStatus::ObjectNameCollision,
                                rssmb_vfs::VfsError::AccessDenied => NtStatus::AccessDenied,
                                rssmb_vfs::VfsError::NotFound => NtStatus::ObjectNameNotFound,
                                rssmb_vfs::VfsError::DirectoryNotEmpty => {
                                    NtStatus::DirectoryNotEmpty
                                }
                                rssmb_vfs::VfsError::DiskFull => NtStatus::DiskFull,
                                _ => NtStatus::InvalidParameter,
                            };
                            error_response_for(Command::SetInfo, status, &req.header)
                        }
                    }
                }
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "set_info: parse rename failed");
                    error_response_for(Command::SetInfo, NtStatus::InvalidParameter, &req.header)
                }
            }
        }
        _ => {
            debug!(
                conn_id = conn_state.conn_id,
                class = class_byte,
                "unsupported set_info class"
            );
            error_response_for(Command::SetInfo, NtStatus::NotSupported, &req.header)
        }
    }
}
