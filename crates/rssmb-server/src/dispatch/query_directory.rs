use super::*;

pub(crate) async fn handle_query_directory(
    _state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let qd_req = match &req.content {
        RequestContent::QueryDirectory(q) => q,
        _ => {
            return error_response_for(
                Command::QueryDirectory,
                NtStatus::InvalidParameter,
                &req.header,
            )
        }
    };

    let file_id_volatile = qd_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::QueryDirectory, status, &req.header),
        };

    // Pipe opens don't support QUERY_DIRECTORY.
    if entry.is_pipe {
        return error_response_for(
            Command::QueryDirectory,
            NtStatus::Other(0xC000_0010),
            &req.header,
        );
    }

    // MS-SMB2 3.3.5.18: an unsupported FileInformationClass fails with
    // STATUS_INVALID_INFO_CLASS (after the handle checks above).
    let Some(info_class) = qd_req.info_class() else {
        debug!(
            conn_id = conn_state.conn_id,
            class = qd_req.file_information_class,
            "unsupported directory info class"
        );
        return error_response_for(
            Command::QueryDirectory,
            NtStatus::InvalidInfoClass,
            &req.header,
        );
    };
    let class_id = u8::from(info_class);

    let pattern = qd_req.file_name.to_string();
    let restart = qd_req.flags.restart_scans() || qd_req.flags.reopen();
    let single = qd_req.flags.return_single_entry();
    let max_len = qd_req.output_buffer_length as usize;

    let mut cursor = entry.dir_cursor.lock().await;
    if restart {
        cursor.entries = None;
        cursor.next = 0;
    }
    let first_call = cursor.entries.is_none();
    if first_call {
        // Snapshot the listing once; later calls page through it.
        let mut all = Vec::new();
        // Synthesize . and .. only for wildcard enumerations.
        if pattern == "*" || pattern.is_empty() {
            all.extend(crate::fsinfo::synthesize_dot_entries());
        }
        match entry
            .vfs
            .query_dir(
                entry.open_id,
                &pattern,
                rssmb_vfs::DirInfoClass::IdBothDirectoryInfo,
                true,
                0,
            )
            .await
        {
            Ok(vfs_entries) => all.extend(vfs_entries),
            Err(e) => {
                debug!(conn_id = conn_state.conn_id, error = %e, "query_dir VFS failed");
                return error_response_for(
                    Command::QueryDirectory,
                    NtStatus::NoSuchFile,
                    &req.header,
                );
            }
        }
        cursor.entries = Some(all);
        cursor.next = 0;
    }

    let all = cursor.entries.as_ref().expect("snapshot set above");
    if cursor.next >= all.len() {
        // MS-SMB2 3.3.5.18: no match on the first query → NO_SUCH_FILE,
        // exhausted cursor → NO_MORE_FILES.
        let status = if first_call {
            NtStatus::NoSuchFile
        } else {
            NtStatus::NoMoreFiles
        };
        return error_response_for(Command::QueryDirectory, status, &req.header);
    }

    // Take as many entries as fit in output_buffer_length.
    let remaining = &all[cursor.next..];
    let limit = if single { 1 } else { remaining.len() };
    let mut take = 0;
    let mut buffer: Option<Vec<u8>> = None;
    for n in 1..=limit {
        match crate::fsinfo::build_directory_buffer(&remaining[..n], class_id) {
            Some(b) if b.len() <= max_len => {
                take = n;
                buffer = Some(b);
            }
            Some(_) => break,
            None => {
                debug!(
                    conn_id = conn_state.conn_id,
                    class = class_id,
                    "unsupported directory info class"
                );
                return error_response_for(
                    Command::QueryDirectory,
                    NtStatus::InvalidInfoClass,
                    &req.header,
                );
            }
        }
    }
    if take == 0 {
        return error_response_for(
            Command::QueryDirectory,
            NtStatus::BufferOverflow,
            &req.header,
        );
    }
    cursor.next += take;
    drop(cursor);

    match buffer {
        Some(buffer) => {
            let response = build_response(
                &req.header,
                ResponseContent::QueryDirectory(rssmb_proto::query_dir::QueryDirectoryResponse {
                    output_buffer: buffer,
                }),
            );
            FramedResponse::Plain(response)
        }
        None => {
            debug!(
                conn_id = conn_state.conn_id,
                class = class_id,
                "unsupported directory info class"
            );
            error_response_for(
                Command::QueryDirectory,
                NtStatus::InvalidInfoClass,
                &req.header,
            )
        }
    }
}
