# READ path profile — rssmb 0.1.2 (b5a41d9), 2026-10-18

Hardware: AMD Ryzen 7 PRO 7840U (8C/16T), share on tmpfs (isolates the
server's own cost from disk latency), kernel CIFS client vers=3.1.1,
docker bridge network, release build with `debug = 1`
(CARGO_PROFILE_RELEASE_DEBUG=1), `perf record -F 299 -g`.

## fio baseline (256M, bs=1M, direct=1, libaio)

| Config | bw | avg lat | implied serial service time |
|---|---|---|---|
| seal ON, iodepth 16 | 391 MiB/s | 49.8 ms | ~2.0 ms/read |
| seal ON, iodepth 4 | 333 MiB/s | 12.2 ms | ~1.5 ms/read |
| seal OFF, iodepth 16 | ~775 MiB/s (implied from lat 20.6 ms) | 20.6 ms | ~0.42 ms/read* |

*seal-off service time derived from latency/depth; the bw line for that run
was lost to log truncation, only the latency line survived.

The structural problem reproduces on faster hardware, scaled: 4× queue
depth buys only +17% (333→391), i.e. the pipeline is serial. The user's
~150 MiB/s @ ~7 ms/read included real-disk latency on slower hardware;
here tmpfs pins the pure server cost at ~1.5–2.0 ms per 1 MiB READ.

## Where the time goes (perf, % of total cycles, children-inclusive)

seal ON / seal OFF:

| Stage | seal ON | seal OFF |
|---|---|---|
| Page faults (`asm_exc_page_fault → do_anonymous_page → alloc_anon_folio`) — kernel zeroing fresh allocations | **42.7%** | 37.2% |
| `clear_highpages_kasan_tagged` (explicit zeroing inside the above) | 9.1% (self) | 9.4% (self) |
| `sendto` (`tcp_sendmsg`) | 9.2% | 18.3% |
| `madvise` (allocator returning huge pages after free) | 9.5% | 7.9% |
| rssmb user frames (copies + AES-GCM + parsing) | ~19–23% | ~27% |
| Everything on threads | **100% on ONE `tokio-rt-worker`** | same |

`is_x86_feature_detected!("aes")` = **true** at runtime on this host.
aes-gcm 0.10 (via `aes` 0.8) uses runtime CPU feature detection
(cpufeatures), and the release workflow RUSTFLAGS
(`-C target-feature=+crt-static -C link-arg=-s`) do not disable it —
AES-NI is in use in both the local and the musl release builds. Crypto is
not the bottleneck; the copies and zeroing around it are.

## READ request lifecycle (code trace, with locations)

1. **Receive** (`connection.rs:426–457`): `read_netbios_payload_for_transport`
   allocates a fresh `Vec<u8>` per frame (size of the request — small for
   READ). Inline on the tokio worker.
2. **Decrypt** (`connection.rs:470–543`, encrypted only): `decrypt_message`
   on the tokio worker.
3. **Parse** (`connection.rs:550`): `parse_payload` under
   `catch_unwind` — small work, per frame.
4. **Dispatch — THE SERIAL BOTTLENECK** (`connection.rs:851`):

   ```rust
   let response = handle_message(state, conn_state, framed, &payload, was_encrypted).await;
   ```

   `read_loop` awaits the full handler (VFS read included) before looping
   to read the next frame. Nothing else on the connection proceeds until
   the response is built, signed, encrypted and pushed to `write_tx`.
   This is why 100% of samples sit on one `tokio-rt-worker` and why
   queue depth cannot help: 16 outstanding client requests are serviced
   strictly one at a time.
5. **VFS read** (`localfs.rs:514–536`):
   - takes a **per-open-handle mutex** (`handle.lock().await`, line 519) —
     concurrent READs on the same open serialize here too, even if
     dispatch were made concurrent;
   - allocates **`vec![0u8; len]` — a fresh zeroed 1 MiB buffer per READ**
     (line 528): the kernel faults in and zeroes 256 fresh pages every
     time (the dominant 42.7% of the profile), then `read(2)` overwrites
     the zeros;
   - the `read(2)` itself runs via tokio's blocking pool (tokio::fs), so
     the syscall is off-worker, but everything around it is not.
6. **Response build** (`dispatch.rs:3680–3683`): `ReadResponse { buffer:
   data.to_vec() }` — **copy #1 of the payload** (all paths).
7. **Encode** (`connection.rs:898`): `encode_response(&resp).to_vec()` —
   **copy #2** (all paths).
8. **Encrypt + re-frame** (`connection.rs:1034–1068`, sealed only):
   `smb2_body.to_vec()` — **copy #3**, then in-place AES-128-GCM
   (AES-NI, fast), then `wire.extend_from_slice(&plaintext)` — **copy #4**.
9. **Write task** drains `write_rx` and `sendto`s the frame — one more
   in-kernel copy (unavoidable), and the only stage that is already
   off the read loop.

Per sealed 1 MiB READ: 1 kernel-zeroed 1 MiB allocation + **4 full 1 MiB
user-space copies** + in-place AES-GCM, all on one core.

## Ranked causes and estimated gains

1. **Serial dispatch** (`connection.rs:851` awaits `handle_message`
   inline). Everything else is irrelevant while one core does all work
   for all connections... on this box 16 threads exist and idle.
   Fix: spawn per-request tasks bounded by the credit window; responses
   through the existing per-connection mpsc to the write task (it already
   exists); keep compounds/related operations sequential.
   **Est. gain: up to N-core scaling, ≥2× on any multi-core host.** This
   is the top fix; it must come first because none of the per-read costs
   below can overlap while dispatch is serial.
2. **Fresh zeroed 1 MiB buffer per READ + 4 copies** (items 5–8 above).
   The page-fault/zeroing path alone is ~40% of cycles; with pooling and
   a zero-copy response path (build the SMB2 header ahead of the payload,
   hand the VFS buffer to the response, single `encrypt_in_place`), the
   per-read CPU cost should drop several-fold.
   **Est. gain: ~1.5–2× single-core throughput.**
3. **Per-open mutex in `read_at`** (`localfs.rs:519`): seek+read under a
   mutex per open. Pread (`read_exact_at`/`pread`) needs no seek and no
   shared-position lock, allowing true parallel reads per open.
   **Est. gain: unlocks fix #1 for single-file clients like fio/CIFS.**
4. **AES-GCM** — not a problem: AES-NI is active; after copies are gone,
   encryption is ~0.2–0.3 ms/MiB. No crypto changes proposed.

Not causes: credit limits (untouched, 1024), max_frame_size, the write
task (already parallel), dialect negotiation.

## Artifacts

- `flamegraph-seal-on.svg`, `flamegraph-seal-off.svg` — flamegraphs
- `perf-seal-on.data`, `perf-seal-off.data` — raw perf.data (F 299, -g)

## Open points

- rssmb user frames are partially unresolved (`0x000055...` addresses) —
  the release binary kept symbols but perf printed raw addresses for some
  frames; the SVGs carry the resolved ones. `addr2line` on
  `perf-seal-*.data` can recover the rest if needed.
- The seal-off bw number is implied from latency (log truncation); the
  latency line and the implied service time are solid.
- This box: tmpfs share + bridge veth adds ~0.1–0.3 ms/round-trip vs
  loopback; the user's absolute numbers will differ but the structure
  (serial single-core pipeline, zeroing-dominated) is hardware-independent
  and matches their symptom exactly.
