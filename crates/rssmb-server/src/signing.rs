//! SMB2 message signing at the wire layer (MS-SMB2 3.3.4.1.1 / 3.3.5.2.4).
//!
//! Verification runs on the raw request bytes before decoding is trusted;
//! signing runs on the encoded response bytes. Both operate per message so
//! compound chains are handled member by member.

use crate::crypto::{sign_message, verify_signature};
use crate::dispatch::SigningState;

const HDR: usize = 64;
const FLAGS_OFF: usize = 16;
const SESSION_ID_OFF: usize = 40;
const SIG_OFF: usize = 48;
const FLAG_SIGNED: u32 = 0x0000_0008;
const CMD_NEGOTIATE: u16 = 0;
const CMD_SESSION_SETUP: u16 = 1;

fn flags(msg: &[u8]) -> u32 {
    u32::from_le_bytes(msg[FLAGS_OFF..FLAGS_OFF + 4].try_into().unwrap())
}
fn session_id(msg: &[u8]) -> u64 {
    u64::from_le_bytes(msg[SESSION_ID_OFF..SESSION_ID_OFF + 8].try_into().unwrap())
}
fn command(msg: &[u8]) -> u16 {
    u16::from_le_bytes(msg[12..14].try_into().unwrap())
}

/// Outcome of checking one request message.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Signature absent and not required, or present and valid.
    Ok,
    /// Signed but signature wrong, or required but unsigned → drop/deny.
    Reject,
}

const FLAG_RELATED: u32 = 0x0000_0004;

/// One member of a compound chain, with its resolved effective session id.
#[derive(Debug, Clone)]
pub struct CompoundMember {
    /// Byte range `[start, end)` in the payload.
    pub range: (usize, usize),
    /// Effective SessionId (related members inherit the previous member's).
    pub effective_sid: u64,
    /// Whether this member is related to the previous one.
    pub related: bool,
    /// The command code (SMB2 command enum value).
    pub cmd: u16,
}

/// Walk a plain (possibly compound) payload and resolve each member's
/// effective SessionId (MS-SMB2 3.3.5.2.7.2): an unrelated member uses its
/// own SessionId; a related member inherits the previous member's effective
/// SessionId and its own header value is ignored. A related member following
/// SESSION_SETUP is rejected — its session (and key) only come into existence
/// while dispatching that SESSION_SETUP, so it could never have been verified.
///
/// Malformed boundaries (truncated, misaligned, first member related) reject
/// the whole frame.
pub fn walk_compound(payload: &[u8]) -> Result<Vec<CompoundMember>, &'static str> {
    let ranges = rssmb_wire_adapter::framing::message_ranges(payload);
    if ranges.is_empty() || ranges.last().map(|r| r.1) != Some(payload.len()) {
        return Err("empty or unterminated compound payload");
    }
    let mut members = Vec::with_capacity(ranges.len());
    let mut prev_sid = 0u64;
    let mut prev_cmd: Option<u16> = None;
    for (s, e) in ranges {
        let msg = &payload[s..e];
        if msg.len() < HDR {
            return Err("compound member shorter than header");
        }
        let related = flags(msg) & FLAG_RELATED != 0;
        let sid = if related {
            if prev_cmd == Some(CMD_SESSION_SETUP) || prev_cmd.is_none() {
                return Err("related member without a prior non-related member");
            }
            prev_sid
        } else {
            session_id(msg)
        };
        members.push(CompoundMember {
            range: (s, e),
            effective_sid: sid,
            related,
            cmd: command(msg),
        });
        prev_sid = sid;
        prev_cmd = Some(command(msg));
    }
    Ok(members)
}

/// Verify every message of a plain (possibly compound) request payload.
///
/// Uses [`walk_compound`] for structure/effective-session resolution, then
/// verifies each member's signature. Any member rejecting rejects the whole
/// frame, so nothing in it is executed.
pub fn verify_frame(payload: &[u8], lookup: impl Fn(u64) -> Option<SigningState>) -> Verdict {
    let members = match walk_compound(payload) {
        Ok(m) => m,
        Err(_) => return Verdict::Reject,
    };
    for m in &members {
        let msg = &payload[m.range.0..m.range.1];
        if verify_request(msg, m.effective_sid, &lookup) == Verdict::Reject {
            return Verdict::Reject;
        }
    }
    Verdict::Ok
}

/// Verify one request message (`msg` = exactly that message's bytes) as
/// belonging to session `sid` (already resolved by the caller).
///
/// `lookup(session_id)` returns the session's signing state if it is an
/// established signed session.
pub fn verify_request(
    msg: &[u8],
    sid: u64,
    lookup: impl Fn(u64) -> Option<SigningState>,
) -> Verdict {
    if msg.len() < HDR {
        return Verdict::Reject;
    }
    let cmd = command(msg);
    let signed = flags(msg) & FLAG_SIGNED != 0;
    // NEGOTIATE is never signed (renegotiation is refused by the connection).
    if cmd == CMD_NEGOTIATE {
        return Verdict::Ok;
    }
    let Some(st) = lookup(sid) else {
        // No established signed session: SessionId 0, a pending
        // SESSION_SETUP, or a guest/anonymous session (never signed).
        // Session validity itself is enforced by dispatch.
        return Verdict::Ok;
    };
    if st.retiring {
        return Verdict::Reject;
    }
    // From here the target is an established signed session. That includes
    // SESSION_SETUP on it (re-authentication), which gets no exemption.
    if !signed {
        // On a session that requires signing every request — CANCEL and
        // SESSION_SETUP included — must be signed.
        return if st.required {
            Verdict::Reject
        } else {
            Verdict::Ok
        };
    }
    let mut copy = msg.to_vec();
    let sig: [u8; 16] = copy[SIG_OFF..SIG_OFF + 16].try_into().unwrap();
    copy[SIG_OFF..SIG_OFF + 16].fill(0);
    if verify_signature(&st.key, &copy, &sig, st.dialect) {
        Verdict::Ok
    } else {
        Verdict::Reject
    }
}

/// Sign every message of an encoded response frame in place.
///
/// `frame` is the NetBIOS-framed response (4-byte transport header first).
/// A message is signed when its session is a signed session and either the
/// session requires signing or `client_signed[i]` (the matching request was
/// signed). STATUS_PENDING interim responses are not signed (3.3.4.1.1).
pub fn sign_response_frame(
    frame: &mut [u8],
    client_signed: &[bool],
    mut lookup: impl FnMut(u64) -> Option<SigningState>,
    mut clear_force_sign: impl FnMut(u64),
) {
    if frame.len() < 4 + HDR {
        return;
    }
    let body = &mut frame[4..];
    let ranges = rssmb_wire_adapter::framing::message_ranges(body);
    for (i, (s, e)) in ranges.into_iter().enumerate() {
        let msg = &mut body[s..e];
        let sid = session_id(msg);
        let Some(st) = lookup(sid) else { continue };
        let status = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        if status == 0x0000_0103 {
            continue; // STATUS_PENDING interim
        }
        let want =
            st.required || st.force_sign_once || client_signed.get(i).copied().unwrap_or(false);
        if st.force_sign_once {
            clear_force_sign(sid);
        }
        if !want {
            continue;
        }
        let f = flags(msg) | FLAG_SIGNED;
        msg[FLAGS_OFF..FLAGS_OFF + 4].copy_from_slice(&f.to_le_bytes());
        msg[SIG_OFF..SIG_OFF + 16].fill(0);
        let sig = sign_message(&st.key, msg, st.dialect);
        msg[SIG_OFF..SIG_OFF + 16].copy_from_slice(&sig);
    }
}

/// Whether each message in a request payload had SMB2_FLAGS_SIGNED set.
pub fn request_signed_flags(payload: &[u8]) -> Vec<bool> {
    rssmb_wire_adapter::framing::message_ranges(payload)
        .into_iter()
        .map(|(s, _)| flags(&payload[s..]) & FLAG_SIGNED != 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DialectConfig;

    fn st(required: bool) -> SigningState {
        SigningState {
            key: vec![7u8; 16],
            required,
            dialect: DialectConfig::Smb21,
            retiring: false,
            force_sign_once: false,
        }
    }

    /// A minimal 64-byte header + 4 body bytes for `cmd` on session 5.
    fn msg(cmd: u16) -> Vec<u8> {
        let mut m = vec![0u8; HDR + 4];
        m[..4].copy_from_slice(b"\xfeSMB");
        m[4..6].copy_from_slice(&64u16.to_le_bytes());
        m[12..14].copy_from_slice(&cmd.to_le_bytes());
        m[SESSION_ID_OFF..SESSION_ID_OFF + 8].copy_from_slice(&5u64.to_le_bytes());
        m
    }

    fn sign(m: &mut [u8], key: &[u8]) {
        let f = flags(m) | FLAG_SIGNED;
        m[FLAGS_OFF..FLAGS_OFF + 4].copy_from_slice(&f.to_le_bytes());
        let sig = sign_message(key, m, DialectConfig::Smb21);
        m[SIG_OFF..SIG_OFF + 16].copy_from_slice(&sig);
    }

    #[test]
    fn valid_signature_accepted() {
        let mut m = msg(5);
        sign(&mut m, &[7u8; 16]);
        assert_eq!(verify_request(&m, 0, |_| Some(st(true))), Verdict::Ok);
    }

    #[test]
    fn tampered_or_wrong_key_rejected() {
        let mut m = msg(5);
        sign(&mut m, &[7u8; 16]);
        let mut t = m.clone();
        t[HDR] ^= 1;
        assert_eq!(verify_request(&t, 0, |_| Some(st(false))), Verdict::Reject);
        let mut w = msg(5);
        sign(&mut w, &[8u8; 16]);
        assert_eq!(verify_request(&w, 0, |_| Some(st(false))), Verdict::Reject);
    }

    #[test]
    fn unsigned_rejected_only_when_required() {
        let m = msg(5);
        assert_eq!(verify_request(&m, 0, |_| Some(st(true))), Verdict::Reject);
        assert_eq!(verify_request(&m, 0, |_| Some(st(false))), Verdict::Ok);
        assert_eq!(
            verify_request(&m, 0, |_| None),
            Verdict::Ok,
            "guest session"
        );
    }

    #[test]
    fn negotiate_exempt_but_reauth_session_setup_is_not() {
        assert_eq!(verify_request(&msg(0), 5, |_| Some(st(true))), Verdict::Ok);
        // Unsigned SESSION_SETUP targeting an established signed session.
        assert_eq!(
            verify_request(&msg(1), 5, |_| Some(st(true))),
            Verdict::Reject
        );
        // ...but a fresh/pending one (no signing state yet) is fine.
        assert_eq!(verify_request(&msg(1), 0, |_| None), Verdict::Ok);
    }

    fn compound(members: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, m) in members.iter().enumerate() {
            let mut m = m.clone();
            let last = i == members.len() - 1;
            if !last {
                let aligned = (m.len() + 7) & !7;
                m.resize(aligned, 0);
                m[20..24].copy_from_slice(&(aligned as u32).to_le_bytes());
            }
            out.extend(m);
        }
        out
    }

    fn related(mut m: Vec<u8>, sid: u64) -> Vec<u8> {
        let f = flags(&m) | FLAG_RELATED;
        m[FLAGS_OFF..FLAGS_OFF + 4].copy_from_slice(&f.to_le_bytes());
        m[SESSION_ID_OFF..SESSION_ID_OFF + 8].copy_from_slice(&sid.to_le_bytes());
        m
    }

    #[test]
    fn related_member_after_session_setup_rejected() {
        // [SESSION_SETUP on pending session 5][related unsigned WRITE]
        let frame = compound(&[msg(1), related(msg(9), u64::MAX)]);
        // Even though 5 has no signing state yet at verification time.
        assert_eq!(verify_frame(&frame, |_| None), Verdict::Reject);
    }

    #[test]
    fn related_member_inherits_previous_session_not_own_header() {
        let key = [7u8; 16];
        // Member 0: signed op on signed session 5. Member 1: related,
        // unsigned, header claims a guest session 9 — must be checked as 5.
        let mut m0 = msg(5);
        sign(&mut m0, &key);
        let m1 = related(msg(8), 9);
        let lookup = |sid: u64| if sid == 5 { Some(st(true)) } else { None };
        assert_eq!(
            verify_frame(&compound(&[m0.clone(), m1]), lookup),
            Verdict::Reject
        );
        // Signed related member verifies against 5's key.
        let mut m1s = related(msg(8), 9);
        sign(&mut m1s, &key);
        // m0 must be re-signed after compound() patches NextCommand.
        let mut frame = compound(&[m0, m1s]);
        let r: Vec<_> = rssmb_wire_adapter::framing::message_ranges(&frame);
        for (s, e) in r {
            frame[s + SIG_OFF..s + SIG_OFF + 16].fill(0);
            let sig = sign_message(&key, &frame[s..e], DialectConfig::Smb21);
            frame[s + SIG_OFF..s + SIG_OFF + 16].copy_from_slice(&sig);
        }
        assert_eq!(verify_frame(&frame, lookup), Verdict::Ok);
    }

    #[test]
    fn unrelated_unsigned_member_on_signed_session_rejected() {
        let mut m0 = msg(5);
        let mut other = msg(5);
        other[SESSION_ID_OFF..SESSION_ID_OFF + 8].copy_from_slice(&9u64.to_le_bytes());
        sign(&mut other, &[1u8; 16]);
        // member 1 (unrelated, session 5) unsigned
        m0[SESSION_ID_OFF..SESSION_ID_OFF + 8].copy_from_slice(&9u64.to_le_bytes());
        let lookup = |sid: u64| if sid == 5 { Some(st(true)) } else { None };
        assert_eq!(
            verify_frame(&compound(&[m0, msg(5)]), lookup),
            Verdict::Reject
        );
    }

    #[test]
    fn first_member_related_rejected_and_truncated_frame_rejected() {
        assert_eq!(verify_frame(&related(msg(5), 5), |_| None), Verdict::Reject);
        assert_eq!(verify_frame(&msg(5)[..40], |_| None), Verdict::Reject);
    }

    #[test]
    fn response_signing_roundtrip() {
        let mut frame = vec![0, 0, 0, (HDR + 4) as u8];
        frame.extend(msg(5));
        sign_response_frame(&mut frame, &[false], |_| Some(st(true)), |_| {});
        let body = frame[4..].to_vec();
        assert!(flags(&body) & FLAG_SIGNED != 0);
        assert_eq!(verify_request(&body, 0, |_| Some(st(true))), Verdict::Ok);
    }

    // --- walk_compound tests ---

    #[test]
    fn walk_single_unrelated_ok() {
        let m = msg(5);
        let members = walk_compound(&m).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].effective_sid, 5);
        assert!(!members[0].related);
    }

    #[test]
    fn walk_related_member_inherits_sid() {
        let key = [7u8; 16];
        let mut m0 = msg(5);
        sign(&mut m0, &key);
        let m1 = related(msg(8), u64::MAX);
        let frame = compound(&[m0.clone(), m1]);
        let members = walk_compound(&frame).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].effective_sid, 5);
        assert!(!members[0].related);
        assert_eq!(
            members[1].effective_sid, 5,
            "related member inherits prev sid"
        );
        assert!(members[1].related);
    }

    #[test]
    fn walk_first_member_related_rejected() {
        assert!(walk_compound(&related(msg(5), 5)).is_err());
    }

    #[test]
    fn walk_truncated_frame_rejected() {
        assert!(walk_compound(&msg(5)[..40]).is_err());
    }

    #[test]
    fn walk_related_after_session_setup_rejected() {
        let frame = compound(&[msg(1), related(msg(9), u64::MAX)]);
        assert!(walk_compound(&frame).is_err());
    }

    #[test]
    fn response_not_signed_when_neither_side_wants_it() {
        let mut frame = vec![0, 0, 0, (HDR + 4) as u8];
        frame.extend(msg(5));
        let before = frame.clone();
        sign_response_frame(&mut frame, &[false], |_| Some(st(false)), |_| {});
        assert_eq!(frame, before);
    }
}
