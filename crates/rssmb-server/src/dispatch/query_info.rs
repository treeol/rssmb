use super::*;

pub(crate) async fn handle_query_info(
    _state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let qi_req = match &req.content {
        RequestContent::QueryInfo(q) => q,
        _ => {
            return error_response_for(Command::QueryInfo, NtStatus::InvalidParameter, &req.header)
        }
    };

    let file_id_volatile = qi_req.file_id.volatile;
    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(status) => return error_response_for(Command::QueryInfo, status, &req.header),
        };

    // Pipe opens: return minimal info for FileStandardInformation, reject rest.
    if entry.is_pipe {
        let info_type_byte = qi_req.info_type as u8;
        let info_class_byte = qi_req.info_class.0;
        let data = match info_type_byte {
            0x01 => match info_class_byte {
                5 => vec![0u8; 24], // FileStandardInformation: zeros for a pipe.
                _ => {
                    debug!(
                        conn_id = conn_state.conn_id,
                        class = info_class_byte,
                        "unsupported pipe info class"
                    );
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::NotSupported,
                        &req.header,
                    );
                }
            },
            _ => {
                return error_response_for(Command::QueryInfo, NtStatus::NotSupported, &req.header);
            }
        };
        let query_response = rssmb_proto::info::QueryInfoResponse::from_bytes(data);
        let response = build_response(&req.header, ResponseContent::QueryInfo(query_response));
        return FramedResponse::Plain(response);
    }

    // Determine the info type and class from the request.
    // The info_type is 1=File, 2=FileSystem, 3=Security, 4=Quota.
    // For File, the info_class byte maps to QueryFileInfoClass values.
    // For FileSystem, the info_class byte maps to QueryFileSystemInfoClass values.
    let info_type_byte = qi_req.info_type as u8;
    let info_class_byte = qi_req.info_class.0;

    let data = match info_type_byte {
        // InfoType::File (0x01)
        0x01 => {
            // Query the VFS for file info
            let info = match entry
                .vfs
                .query_info(entry.open_id, rssmb_vfs::InfoClass::FileStandardInfo)
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "query_info VFS failed");
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            };
            match info_class_byte {
                4 => crate::fsinfo::file_basic_info(&info), // FileBasicInformation
                5 => crate::fsinfo::file_standard_info(&info), // FileStandardInformation
                6 => crate::fsinfo::file_internal_info(&info), // FileInternalInformation
                7 => crate::fsinfo::file_ea_info(),         // FileEaInformation
                18 => {
                    // FileAllInformation — what Linux cifs.ko uses to stat.
                    let ro = tree_read_only(conn_state, entry.tree_id).await;
                    let access = if ro { 0x0012_00a9 } else { 0x001f_01ff };
                    crate::fsinfo::file_all_info(&info, &entry.path, access)
                }
                22 => crate::fsinfo::file_stream_info(&info), // FileStreamInformation
                34 => crate::fsinfo::file_network_open_info(&info), // FileNetworkOpenInformation
                35 => crate::fsinfo::file_attribute_tag_info(&info), // FileAttributeTagInformation
                _ => {
                    debug!(
                        conn_id = conn_state.conn_id,
                        class = info_class_byte,
                        "unsupported file info class"
                    );
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidInfoClass,
                        &req.header,
                    );
                }
            }
        }
        // InfoType::FileSystem (0x02)
        0x02 => {
            let stats = match entry.vfs.fs_stats(entry.open_id).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "fs_stats VFS failed");
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            };
            let share_name = {
                let trees_ref = conn_state.trees_ref();
                let trees = trees_ref.read().await;
                trees
                    .get(&tree_id)
                    .map(|t| t.share_name.clone())
                    .unwrap_or_default()
            };
            match info_class_byte {
                1 => crate::fsinfo::fs_volume_info(&share_name), // FileFsVolumeInformation
                3 => crate::fsinfo::fs_size_info(&stats),        // FileFsSizeInformation
                4 => crate::fsinfo::fs_device_info(),            // FileFsDeviceInformation
                5 => crate::fsinfo::fs_attribute_info(),         // FileFsAttributeInformation
                7 => crate::fsinfo::fs_full_size_info(&stats),   // FileFsFullSizeInformation
                11 => crate::fsinfo::fs_sector_size_info(&stats), // FileFsSectorSizeInformation
                _ => {
                    debug!(
                        conn_id = conn_state.conn_id,
                        class = info_class_byte,
                        "unsupported filesystem info class"
                    );
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidInfoClass,
                        &req.header,
                    );
                }
            }
        }
        // InfoType::Security (0x03) — synthesize a minimal SD from POSIX mode.
        0x03 => {
            // Only DACL/OWNER/GROUP are supported. SACL requests require
            // ACCESS_SYSTEM_SECURITY which we don't grant.
            let additional_info = u32::from_le_bytes(qi_req.additional_info.into_bytes());
            let sec_info = match entry.vfs.query_security(entry.open_id).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(conn_id = conn_state.conn_id, error = %e, "query_security VFS failed");
                    return error_response_for(
                        Command::QueryInfo,
                        NtStatus::InvalidParameter,
                        &req.header,
                    );
                }
            };
            let sd = crate::fsinfo::synthesize_security_descriptor(&sec_info, additional_info);
            if sd.is_empty() {
                return error_response_for(
                    Command::QueryInfo,
                    NtStatus::Other(0xC000_0001),
                    &req.header,
                );
            }
            sd
        }
        // InfoType::Quota (0x04)
        0x04 => {
            return error_response_for(Command::QueryInfo, NtStatus::NotSupported, &req.header);
        }
        _ => {
            return error_response_for(Command::QueryInfo, NtStatus::InvalidInfoClass, &req.header);
        }
    };

    let query_response = rssmb_proto::info::QueryInfoResponse::from_bytes(data);
    let response = build_response(&req.header, ResponseContent::QueryInfo(query_response));
    FramedResponse::Plain(response)
}
