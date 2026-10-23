use super::*;

pub(crate) fn handle_echo(req_header: &Header) -> FramedResponse {
    use rssmb_proto::echo::EchoResponse;
    let echo_response = EchoResponse::default();
    let response = build_response(req_header, ResponseContent::Echo(echo_response));
    FramedResponse::Plain(response)
}

// ── Phase 3: File serving handlers ─────────────────────────────────────

/// Allocate a fresh, non-zero SMB2 SessionId (random with collision check
/// against the connection's sessions, pending sessions, and the global
/// session registry).
pub(crate) fn next_session_id(conn_state: &ConnState, state: &ServerState) -> u64 {
    use rand::Rng;
    loop {
        let id: u64 = rand::thread_rng().gen_range(1..u64::MAX);
        // Check against active sessions and pending sessions.
        let sessions = conn_state.sessions.try_read();
        let pending = conn_state.pending_sessions.try_read();
        let in_sessions = sessions
            .as_ref()
            .map(|s| s.iter().any(|sess| sess.id == id))
            .unwrap_or(false);
        let in_pending = pending.as_ref().map(|p| p.contains(&id)).unwrap_or(false);
        let in_registry = state.session_registry.read().unwrap().contains_key(&id);
        if !in_sessions && !in_pending && !in_registry {
            return id;
        }
    }
}

/// Allocate a per-connection TreeId (starts at 1, never 0 or 0xFFFFFFFF).
pub(crate) fn next_tree_id(conn_state: &ConnState) -> u32 {
    conn_state
        .next_tree_id_ref()
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Allocate a per-connection FileId: volatile from a counter, persistent random.
pub(crate) fn next_file_id(conn_state: &ConnState) -> rssmb_proto::create::FileId {
    let volatile = conn_state
        .next_volatile_id_ref()
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Skip the sentinel value (0xFFFFFFFFFFFFFFFF) used by substitute_file_id.
    let volatile = if volatile == u64::MAX { 0 } else { volatile };
    let persistent = conn_state.persistent_base_val().wrapping_add(volatile);
    rssmb_proto::create::FileId {
        persistent,
        volatile,
    }
}
