# Lock Audit — std::sync guards across .await + dual-lock ServerState fields

Inventory taken 2026-10-23 on `refactor/dispatch-split` branch.

## 1. std::sync lock guards held across .await points

**No confirmed instances found.** All std::sync guards in the server
crate are scoped to temporary expressions or explicit `let` bindings
that are dropped before the next `.await`:

- `send_unsolicited` (async_helpers.rs:87-94,106): `encryption_ref().read().unwrap()`
  and `signing_ref().read().unwrap()` are scoped inside `if let` expressions that
  complete (and drop the guard) before the `.await` at `write_tx.send` (line 163).
- `teardown_previous_session` (mod.rs:1155-1278): `session_registry.read/write()`,
  `retired_sessions.write()` — each in a scoped block dropped before subsequent
  `.await` calls.
- `handle_plain` retired-session gate (mod.rs:981-984):
  `state.retired_sessions.read().unwrap().contains(&sid)` is a temporary
  dropped at end of statement — not held across await.
- `handle_plain` negotiate gate (mod.rs:909-926): uses `tokio::sync::Mutex`
  (`negotiate_record.lock().await`), not std — safe across awaits.

**Uninspected** (not fully read by the audit subagent):
- `ioctl.rs` rec_guard usage (lines 95-96, 185-186) — may hold a std
  RwLock guard; needs a manual check before the next hardening pass.
- `quic.rs:650` `_held_guard` and `connection.rs:650,1880` guard usage.

## 2. ServerState fields with dual std/tokio lock variants

| Field pair | std variant | tokio variant | Notes |
|---|---|---|---|
| **identities** | `identities_swap: StdRwLock<Arc<IdentityStore>>` (lib.rs:130) | `identities: Arc<IdentityStore>` (lib.rs:123) | Identity store accessible both as an unlocked boot Arc and a live-reloadable std-RwLock-swap. High-risk: a reader using the boot Arc won't see a reload. |
| **shares** | `shares_swap: StdRwLock<Arc<HashMap<String, ShareConfig>>>` (lib.rs:211) | `config.shares` (immutable via `Arc<ServerConfig>`) | Same share data reachable via the immutable config Arc and the std-RwLock swap. Medium-risk: the config path never sees live swaps. |
| **sessions** | `session_registry: Arc<StdRwLock<HashMap<u64, Arc<SessionShared>>>` (lib.rs:155) | `sessions: Arc<tokio::sync::RwLock<Vec<Arc<Session>>>` (lib.rs:117) | Parallel session tables, one per lock flavor. Removed/inserted in tandem by `teardown_previous_session` (mod.rs:1261-1266). Medium-risk: drift if one is modified without the other. |
| **SessionShared/SessionArcs** | `signing: Arc<StdRwLock<...>>`, `encryption: Arc<StdRwLock<...>>` (mod.rs:175-176) | `trees: Arc<tokio::sync::RwLock<...>>`, `opens: Arc<tokio::sync::RwLock<...>>` (mod.rs:171-172) | Mixed lock flavors over the same session's state. `SessionArcs` (mod.rs:205) duplicates the same Arcs. Medium-risk: the split is by data type, not by access pattern, so the lock flavors don't match usage. |

## Next debt items (not this branch)

1. Inspect the uninspected std-guard sites (ioctl.rs, quic.rs, connection.rs).
2. Unify the dual-lock pairs: pick one lock flavor per field and use it
   consistently, or document why the split is safe.
3. The `identities` boot-Arc vs `identities_swap` std-RwLock is the highest
   risk — a reader using the boot path won't see a live reload.