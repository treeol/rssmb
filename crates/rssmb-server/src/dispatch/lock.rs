use super::*;

pub(crate) fn rearm_lock_sequence(
    seq_element: &Option<Arc<std::sync::Mutex<[u8; 64]>>>,
    seq_bucket: usize,
    seq_value: u8,
) {
    if let Some(arr) = seq_element {
        if (1..=64).contains(&seq_bucket) {
            arr.lock().unwrap()[seq_bucket - 1] = seq_value;
        }
    }
}

/// LOCK — acquire or release byte-range locks (MS-SMB2 3.3.5.14).
///
/// Processes a LOCK request containing one or more lock elements. Each element
/// specifies a byte range and flags (shared/exclusive/unlock/fail-immediately).
/// Locks are tracked in the global `OpenTable` keyed by file identity, so
/// conflicts across sessions and trees are enforced.
///
/// Only FAIL_IMMEDIATELY is supported in this phase. Blocking (async) locks
/// are deferred — the client gets `LOCK_NOT_GRANTED` if the range is
/// contended instead of waiting for the holder to release.
pub(crate) async fn handle_lock(
    state: &ServerState,
    conn_state: &ConnState,
    req: rssmb_proto::plain::PlainRequest,
) -> FramedResponse {
    let lock_req = match &req.content {
        RequestContent::Lock(l) => l,
        _ => return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header),
    };

    // lock_count == 0 is INVALID_PARAMETER (torture `valid-request`,
    // MS-SMB2 2.2.21: LockCount must be at least 1).
    if lock_req.locks.is_empty() {
        return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
    }

    let session_id = req.header.session_id;
    let tree_id = req.header.tree_id.unwrap_or(0);

    // LOCK-specific: validate the persistent half of the FileId (forged
    // persistent → FILE_CLOSED, torture valid-request lock.c:133).
    if let Err(status) = check_lock_file_id_persistent(conn_state, &lock_req.file_id).await {
        return error_response_for(Command::Lock, status, &req.header);
    }

    // LockSequence replay detection (MS-SMB2 3.3.5.14; smbd
    // smbd_smb2_lock_send): the server advertises MULTI_CHANNEL, so
    // checking is enabled for all opens (spec SHOULD; also enabled for
    // durable handles). Bucket = sequence >> 4 (only 1..=64 valid);
    // value = sequence & 0xF. A replayed (bucket == stored value) request
    // is ignored: the request returns the ORIGINAL result — replayed
    // success is succeeded silently again, replayed failure is also
    // suppressed, which is what the torture replay_* subtests assert.
    let lock_sequence = lock_req.lock_sequence;
    let seq_bucket = (lock_sequence >> 4) as usize;
    let seq_value = (lock_sequence & 0xF) as u8;

    // Look up the open handle, validating session/tree ownership. A handle
    // that is gone (closed/tdis/logoff) is FILE_CLOSED for LOCK (torture
    // cancel-logoff lock.c:1166 and valid-request lock.c:133 both assert
    // FILE_CLOSED here; most other commands keep INVALID_HANDLE).
    let file_id_volatile = lock_req.file_id.volatile;
    let entry =
        match lookup_open_for_session(conn_state, session_id, tree_id, file_id_volatile).await {
            Ok(e) => e,
            Err(NtStatus::InvalidHandle) => {
                return error_response_for(Command::Lock, NtStatus::FileClosed, &req.header)
            }
            Err(status) => return error_response_for(Command::Lock, status, &req.header),
        };

    // Pipe opens don't support byte-range locks.
    if entry.is_pipe {
        return error_response_for(Command::Lock, NtStatus::NotSupported, &req.header);
    }

    // We need the stable file identity to key into the global lock table.
    let file_id = match entry.file_id {
        Some(fid) => fid,
        None => return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header),
    };

    // LockSequence check (needs the open; see comment above). smbd runs
    // this BEFORE parsing element flags — a replayed request short-circuits
    // to OK regardless of its content.
    let seq_element: Option<Arc<std::sync::Mutex<[u8; 64]>>> = if (1..=64).contains(&seq_bucket) {
        Some(entry.lock_sequence_array.clone())
    } else {
        None
    };
    if let Some(arr) = &seq_element {
        let mut a = arr.lock().unwrap();
        let stored = &mut a[seq_bucket - 1];
        if *stored == seq_value {
            // Replay of an already-successful request: ignore completely
            // (return OK, touch nothing) — smbd tevent_req_done path.
            return build_lock_ok(&req);
        }
        // Not a replay: invalidate the bucket while processing; it is
        // re-armed with the incoming value only on success (matching
        // smbd's cleanup fn).
        *stored = 0xFF;
    }

    // Process the lock elements exactly like smbd (source3/smbd/smb2_lock.c,
    // verified against torture valid-request/unlock/multiple-unlock):
    //
    // 1. First-element flags switch (pre-loop):
    //    - SHARED or EXCLUSIVE alone (no FAIL_IMMEDIATELY) with >1 element
    //      → INVALID_PARAMETER; alone it is a BLOCKING lock (K5 pends on
    //      conflict; a conflict-free blocking lock grants immediately).
    //    - SHARED|FI, EXCLUSIVE|FI → normal immediate locks.
    //    - UNLOCK → the whole request is an unlock request (only the first
    //      element may carry the UNLOCK bit, MS-SMB2 3.3.5.14).
    //    - anything else (0, type bit | UNLOCK, stray bits) →
    //      INVALID_PARAMETER before any state changes.
    // 2. Non-unlock requests with >1 element: every element must carry
    //    FAIL_IMMEDIATELY (MS-SMB2 3.3.5.14.2 SHOULD) → INVALID_PARAMETER.
    // 3. Unlock requests: ALL unlock elements are processed first (applied
    //    unlocks stay applied); the first missing range fails the request
    //    with RANGE_NOT_LOCKED (deferred-invalid elements lose to a real
    //    unlock miss); invalid (type-bit/unknown) elements then fail with
    //    INVALID_PARAMETER (MS-SMB2 3.3.5.14.1, torture multiple-unlock
    //    Test4/Test10).
    use rssmb_proto::lock::lock_flags;

    let elements = &lock_req.locks;
    let first_flags = elements[0].flags;
    let isunlock = first_flags == lock_flags::UNLOCK;

    match first_flags {
        lock_flags::SHARED | lock_flags::EXCLUSIVE => {
            if elements.len() > 1 {
                return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
            }
        }
        f if f == lock_flags::SHARED | lock_flags::FAIL_IMMEDIATELY
            || f == lock_flags::EXCLUSIVE | lock_flags::FAIL_IMMEDIATELY =>
        {
            // SHARED|FI or EXCLUSIVE|FI — normal immediate lock.
        }
        lock_flags::UNLOCK => {}
        _ => {
            return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
        }
    }

    if !isunlock && elements.len() > 1 {
        for el in elements {
            if el.flags & lock_flags::FAIL_IMMEDIATELY == 0 {
                return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
            }
        }
    }

    let mut acquired: Vec<(u64, u64, bool)> = Vec::new();

    if isunlock {
        let mut saw_invalid = false;
        for element in elements {
            if element.flags != lock_flags::UNLOCK {
                // Type bit | UNLOCK or unknown flags: deferred error — all
                // valid unlock elements are processed first.
                saw_invalid = true;
                continue;
            }
            if let Err(_miss) = state
                .open_table
                .release_range_lock(file_id, entry.open_id, element.offset, element.length)
                .await
            {
                return error_response_for(Command::Lock, NtStatus::RangeNotLocked, &req.header);
            }
        }
        if saw_invalid {
            return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
        }
        rearm_lock_sequence(&seq_element, seq_bucket, seq_value);
        return build_lock_ok(&req);
    }

    for element in elements {
        let flags = element.flags;
        let offset = element.offset;
        let length = element.length;
        let exclusive = flags & lock_flags::EXCLUSIVE != 0;
        // A lock element without FAIL_IMMEDIATELY is a BLOCKING lock
        // (MS-SMB2 3.3.5.14); SHARED/EXCLUSIVE-only first elements were
        // validated above. Blocking only applies to the single-element
        // request (the multi-element case already failed validation).
        let blocking = flags & lock_flags::FAIL_IMMEDIATELY == 0;

        // Per-element validation (smbd's second switch): a non-unlock
        // request accepts only SHARED, EXCLUSIVE, SHARED|FI or
        // EXCLUSIVE|FI — anything else (0, type|FI mixtures like
        // SHARED-only on a later element, UNLOCK, unknown bits) is
        // INVALID_PARAMETER (torture valid-request flag permutations).
        match flags {
            lock_flags::SHARED | lock_flags::EXCLUSIVE => {}
            f if f == lock_flags::SHARED | lock_flags::FAIL_IMMEDIATELY
                || f == lock_flags::EXCLUSIVE | lock_flags::FAIL_IMMEDIATELY => {}
            _ => {
                for (o, l, _) in &acquired {
                    let _ = state
                        .open_table
                        .release_range_lock(file_id, entry.open_id, *o, *l)
                        .await;
                }
                return error_response_for(Command::Lock, NtStatus::InvalidParameter, &req.header);
            }
        }

        // >63-bit lock requests: per MS-FSA (and Samba's byte_range_valid),
        // INVALID_LOCK_RANGE only when (offset + length - 1) wraps AND
        // length != 0 — so offset=u64::MAX with length=1 (the single last
        // byte) is a VALID lock (torture lock "Trying max/1 lock" asserts
        // OK at lock.c:747).
        if length != 0 && (length - 1) > u64::MAX - offset {
            for (o, l, _) in &acquired {
                let _ = state
                    .open_table
                    .release_range_lock(file_id, entry.open_id, *o, *l)
                    .await;
            }
            return error_response_for(Command::Lock, NtStatus::InvalidLockRange, &req.header);
        }

        // Zero-length locks are VALID entries (torture `lock` "Trying 0/0
        // lock" and `zerobytelength` — MS-SMB2 2.2.21 allows Length 0;
        // smbd treats them like any other stacked entry). The u128 overlap
        // math makes a 0-length range conflict with nothing, and only an
        // exact (offset, 0) unlock removes it.
        match state
            .open_table
            .acquire_range_lock(
                file_id,
                entry.open_id,
                session_id,
                tree_id,
                offset,
                length,
                exclusive,
            )
            .await
        {
            Ok(()) => {
                acquired.push((offset, length, exclusive));
            }
            Err(_conflict) => {
                // Blocking lock (no FAIL_IMMEDIATELY): pend until the
                // conflicting range is released, the request is cancelled,
                // or the server-side timeout — then either grant
                // (STATUS_OK async completion) or fail LOCK_NOT_GRANTED
                // (MS-SMB2 3.3.5.14; torture async/cancel/cancel-tdis/
                // cancel-logoff).
                if blocking {
                    let message_id = req.header.message_id;
                    let (wake_tx, mut wake_rx) = tokio::sync::watch::channel(false);
                    let waiter = opens::LockWaiter {
                        file_id,
                        open_id: entry.open_id,
                        elements: vec![(offset, length, exclusive)],
                        wake: wake_tx,
                    };
                    let rx = state.open_table.register_lock_waiter(waiter).await;
                    let _ = rx;
                    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
                    conn_state.pending_async.lock().await.insert(
                        message_id,
                        AsyncOp {
                            command: Command::Lock,
                            session_id,
                            tree_id,
                            cancel: cancel_tx,
                            notify_handle: None,
                            watched_file_id: None,
                            lock_open_volatile: Some(file_id_volatile),
                        },
                    );
                    let mut pending_hdr = req.header.clone();
                    pending_hdr.status = NtStatus::Pending.to_u32();
                    pending_hdr.to_async(message_id);
                    pending_hdr.flags = pending_hdr.flags.with_server_to_redir(true);
                    let pending_resp = PlainResponse {
                        header: pending_hdr,
                        content: ResponseContent::Error(rssmb_proto::error::ErrorResponse {
                            error_data: vec![],
                        }),
                    };
                    let conn_clone = conn_state.clone();
                    let req_header = req.header.clone();
                    let open_table = state.open_table.clone();
                    let entry_open_id = entry.open_id;
                    let client_signed = req.header.flags.signed();
                    tokio::spawn(async move {
                        let timeout = tokio::time::sleep(std::time::Duration::from_secs(35));
                        tokio::pin!(timeout);
                        let granted = tokio::select! {
                            _ = wake_rx.changed() => true,
                            _ = timeout => false,
                            _ = cancel_rx => {
                                conn_clone.pending_async.lock().await.remove(&message_id);
                                return;
                            }
                        };
                        // Ownership rule: the completion is sent only by the
                        // task that successfully removes the pending_async
                        // entry. CLOSE/TDIS/LOGOFF sweeps complete pended
                        // locks out-of-band and remove the entry first, so a
                        // woken watcher whose entry is gone must stay silent
                        // (a second response for the same MessageId is
                        // INVALID_NETWORK_RESPONSE for the client).
                        if conn_clone
                            .pending_async
                            .lock()
                            .await
                            .remove(&message_id)
                            .is_none()
                        {
                            return;
                        }
                        // Re-check and apply atomically; a lost race (another
                        // waiter or request grabbed the range) fails.
                        let outcome = if granted
                            && open_table
                                .acquire_range_lock(
                                    file_id,
                                    entry_open_id,
                                    session_id,
                                    tree_id,
                                    offset,
                                    length,
                                    exclusive,
                                )
                                .await
                                .is_ok()
                        {
                            NtStatus::Success
                        } else {
                            NtStatus::LockNotGranted
                        };
                        let mut resp = build_response(
                            &req_header,
                            ResponseContent::Lock(rssmb_proto::lock::LockResponse::default()),
                        );
                        resp.header.to_async(message_id);
                        resp.header.status = outcome.to_u32();
                        resp.header.credit_charge = 0;
                        resp.header.credit_request = 0;
                        send_unsolicited(&conn_clone, &FramedResponse::Plain(resp), client_signed)
                            .await;
                    });
                    return FramedResponse::Plain(pending_resp);
                }
                // FAIL_IMMEDIATELY → LOCK_NOT_GRANTED.
                for (o, l, _) in &acquired {
                    let _ = state
                        .open_table
                        .release_range_lock(file_id, entry.open_id, *o, *l)
                        .await;
                }
                return error_response_for(Command::Lock, NtStatus::LockNotGranted, &req.header);
            }
        }
    }

    if !acquired.is_empty() {
        let (breaks, waiters) = state
            .open_table
            .break_for_op(file_id, Some(entry.open_id), opens::ConflictOp::Lock)
            .await;
        send_break_notifications(&breaks).await;
        state.open_table.arm_break_timers(&waiters);
    }

    rearm_lock_sequence(&seq_element, seq_bucket, seq_value);
    fn build_lock_ok(req: &rssmb_proto::plain::PlainRequest) -> FramedResponse {
        FramedResponse::Plain(build_response(
            &req.header,
            ResponseContent::Lock(rssmb_proto::lock::LockResponse::default()),
        ))
    }

    build_lock_ok(&req)
}
