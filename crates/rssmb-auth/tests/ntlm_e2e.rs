//! End-to-end NTLM authentication tests.
//!
//! These drive `NtlmAuthProvider::step()` with tokens produced by sspi's
//! *client-side* NTLM implementation — real NEGOTIATE / CHALLENGE /
//! AUTHENTICATE messages, real NTLMv2 proofs, real AUTHENTICATE MICs and
//! KEY_EXCH session keys. Unit tests cover the primitives in isolation;
//! these cover the conversation, which is where the regressions in
//! 29daa90 (SPNEGO tag), 6435ee9 (extra MIC round) and c3109a2
//! (complete_auth_token NoCredentials) lived.

use std::sync::Arc;

use rssmb_auth::{
    spnego, AuthError, AuthProvider, AuthState, AuthStep, IdentityStore, NtlmAuthProvider,
};
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm,
    SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};

const USER: &str = "alice";
const PASSWORD: &str = "TestPass123";

/// SPNEGO OID 1.3.6.1.5.5.2 and NTLMSSP OID 1.3.6.1.4.1.311.2.2.10.
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
const NTLMSSP_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

// ---------------------------------------------------------------------------
// Helpers

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match value.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

/// negTokenInit as Windows/Samba send it: mechTypes [0], mechToken [2].
fn neg_token_init(ntlm: &[u8]) -> Vec<u8> {
    let mech_types = der(0xA0, &der(0x30, &der(0x06, NTLMSSP_OID)));
    let mech_token = der(0xA2, &der(0x04, ntlm));
    let seq = der(0x30, &[mech_types, mech_token].concat());
    der(0x60, &[der(0x06, SPNEGO_OID), der(0xA0, &seq)].concat())
}

/// negTokenResp carrying a responseToken [2].
fn neg_token_resp(ntlm: &[u8]) -> Vec<u8> {
    der(0xA1, &der(0x30, &der(0xA2, &der(0x04, ntlm))))
}

fn provider(guest_access: bool) -> NtlmAuthProvider {
    let store =
        IdentityStore::from_users([(USER.to_string(), PASSWORD.to_string(), String::new(), false)]);
    NtlmAuthProvider::with_identity_store(Arc::new(store), guest_access)
}

/// sspi client-side NTLM.
struct Client {
    ntlm: Ntlm,
    creds: Option<sspi::AuthIdentityBuffers>,
}

impl Client {
    fn new(user: &str, password: &str) -> Self {
        let identity = AuthIdentity {
            username: Username::parse(user).unwrap(),
            password: password.to_string().into(),
        };
        let mut ntlm = Ntlm::new();
        let creds = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .unwrap()
            .credentials_handle;
        Self { ntlm, creds }
    }

    /// One client leg. `input` is the raw NTLMSSP server token (empty on
    /// the first leg). Returns the raw NTLMSSP client token.
    fn step(&mut self, input: &[u8]) -> Vec<u8> {
        let mut input_buf = [SecurityBuffer::new(input.to_vec(), BufferType::Token)];
        let mut output_buf = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.creds)
            .with_context_requirements(
                ClientRequestFlags::INTEGRITY
                    | ClientRequestFlags::CONFIDENTIALITY
                    | ClientRequestFlags::ALLOCATE_MEMORY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name("cifs/rssmb")
            .with_output(&mut output_buf);
        if !input.is_empty() {
            builder = builder.with_input(&mut input_buf);
        }
        let result = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .unwrap()
            .resolve_to_result()
            .unwrap();
        if matches!(
            result.status,
            SecurityStatus::CompleteNeeded | SecurityStatus::CompleteAndContinue
        ) {
            self.ntlm.complete_auth_token(&mut output_buf).unwrap();
        }
        output_buf[0].buffer.clone()
    }

    fn session_key(&mut self) -> Vec<u8> {
        self.ntlm
            .query_context_session_key()
            .unwrap()
            .session_key
            .as_ref()
            .clone()
    }
}

fn continue_token(step: Result<AuthStep, AuthError>) -> Vec<u8> {
    match step {
        Ok(AuthStep::Continue { output_token }) => output_token,
        other => panic!("expected Continue, got {other:?}"),
    }
}

/// Run NEGOTIATE → CHALLENGE → AUTHENTICATE and return the provider's
/// verdict on the AUTHENTICATE leg.
async fn run(
    provider: &NtlmAuthProvider,
    client: &mut Client,
    state: &mut AuthState,
    spnego_framing: bool,
) -> Result<AuthStep, AuthError> {
    let negotiate = client.step(&[]);
    let first = if spnego_framing {
        neg_token_init(&negotiate)
    } else {
        negotiate
    };
    let challenge_wrapped = continue_token(provider.step(&first, state).await);
    let challenge = spnego::extract_ntlm_token(&challenge_wrapped).unwrap();
    if !spnego_framing {
        assert_eq!(challenge, challenge_wrapped, "raw framing must reply raw");
    }

    let authenticate = client.step(&challenge);
    let second = if spnego_framing {
        neg_token_resp(&authenticate)
    } else {
        authenticate
    };
    provider.step(&second, state).await
}

fn expect_complete(step: Result<AuthStep, AuthError>) -> (Vec<u8>, Vec<u8>, rssmb_auth::Identity) {
    match step {
        Ok(AuthStep::Complete {
            output_token,
            session_key,
            identity,
        }) => (output_token, session_key, identity),
        other => panic!("expected Complete, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests

#[tokio::test]
async fn raw_ntlmssp_valid_credentials_complete() {
    let provider = provider(false);
    let mut client = Client::new(USER, PASSWORD);
    let mut state = AuthState::new();

    let (_, session_key, identity) =
        expect_complete(run(&provider, &mut client, &mut state, false).await);
    assert_eq!(identity.username, USER);
    assert!(!identity.is_guest);
    assert_eq!(
        session_key,
        client.session_key(),
        "server and client must derive the same (exported) session key"
    );
}

#[tokio::test]
async fn spnego_valid_credentials_complete() {
    let provider = provider(false);
    let mut client = Client::new(USER, PASSWORD);
    let mut state = AuthState::new();

    let (output_token, session_key, identity) =
        expect_complete(run(&provider, &mut client, &mut state, true).await);
    assert_eq!(identity.username, USER);
    assert_eq!(session_key, client.session_key());
    // Final negTokenResp must be SPNEGO accept-completed.
    assert_eq!(
        output_token.first(),
        Some(&0xA1),
        "accept-completed negTokenResp"
    );
}

#[tokio::test]
async fn username_is_case_insensitive() {
    let provider = provider(false);
    let mut client = Client::new("ALICE", PASSWORD);
    let mut state = AuthState::new();
    let (_, _, identity) = expect_complete(run(&provider, &mut client, &mut state, true).await);
    assert!(identity.username.eq_ignore_ascii_case(USER));
}

#[tokio::test]
async fn follow_up_round_after_complete_is_complete() {
    // Samba/Windows may send one more negTokenResp (mechListMIC or empty)
    // after accept-completed. It must not trigger a new auth or a failure.
    let provider = provider(false);
    let mut client = Client::new(USER, PASSWORD);
    let mut state = AuthState::new();
    let (_, key1, _) = expect_complete(run(&provider, &mut client, &mut state, true).await);

    let empty_resp = der(0xA1, &der(0x30, &der(0xA0, &der(0x0A, &[0]))));
    let (_, key2, identity) = expect_complete(provider.step(&empty_resp, &mut state).await);
    assert_eq!(key1, key2);
    assert_eq!(identity.username, USER);
}

#[tokio::test]
async fn wrong_password_is_logon_failure() {
    let provider = provider(true);
    let mut client = Client::new(USER, "wrong-password");
    let mut state = AuthState::new();
    match run(&provider, &mut client, &mut state, true).await {
        Err(AuthError::LogonFailure(_)) => {}
        other => panic!("expected LogonFailure, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_user_is_logon_failure_even_with_guest_enabled() {
    let provider = provider(true);
    let mut client = Client::new("mallory", PASSWORD);
    let mut state = AuthState::new();
    match run(&provider, &mut client, &mut state, true).await {
        Err(AuthError::LogonFailure(_)) => {}
        other => panic!("expected LogonFailure (never guest), got {other:?}"),
    }
}

/// Build a type-3 AUTHENTICATE with the given LM / NT / user payloads.
fn handmade_authenticate(lm: &[u8], nt: &[u8], user: &[u8]) -> Vec<u8> {
    const HEADER: usize = 64;
    let mut msg = b"NTLMSSP\0".to_vec();
    msg.extend_from_slice(&3u32.to_le_bytes());
    let mut payload = Vec::new();
    // Field order: LM @12, NT @20, Domain @28, User @36, Workstation @44, EncRSK @52.
    for data in [lm, nt, &[][..], user, &[][..], &[][..]] {
        let offset = (HEADER + payload.len()) as u32;
        msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(data.len() as u16).to_le_bytes());
        msg.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(data);
    }
    msg.extend_from_slice(&0x0008_8205u32.to_le_bytes()); // NegotiateFlags
    assert_eq!(msg.len(), HEADER);
    msg.extend_from_slice(&payload);
    msg
}

async fn after_challenge(provider: &NtlmAuthProvider, state: &mut AuthState) {
    let mut client = Client::new(USER, PASSWORD);
    let negotiate = client.step(&[]);
    continue_token(provider.step(&neg_token_init(&negotiate), state).await);
}

#[tokio::test]
async fn anonymous_authenticate_becomes_guest_when_enabled() {
    for lm in [&[][..], &[0u8][..]] {
        let provider = provider(true);
        let mut state = AuthState::new();
        after_challenge(&provider, &mut state).await;
        let anon = handmade_authenticate(lm, &[], &[]);
        let (_, session_key, identity) =
            expect_complete(provider.step(&neg_token_resp(&anon), &mut state).await);
        assert!(identity.is_guest);
        assert!(session_key.is_empty(), "guest sessions have no key");
    }
}

#[tokio::test]
async fn anonymous_authenticate_rejected_when_guest_disabled() {
    let provider = provider(false);
    let mut state = AuthState::new();
    after_challenge(&provider, &mut state).await;
    let anon = handmade_authenticate(&[], &[], &[]);
    match provider.step(&neg_token_resp(&anon), &mut state).await {
        Err(AuthError::LogonFailure(_)) => {}
        other => panic!("expected LogonFailure, got {other:?}"),
    }
}

#[tokio::test]
async fn named_user_without_nt_response_is_rejected_with_clear_reason() {
    // Not anonymous (user name set) but no proof: must fail, and must not
    // be passed to sspi (which reports an opaque "cannot be empty").
    let provider = provider(true);
    let mut state = AuthState::new();
    after_challenge(&provider, &mut state).await;
    let user: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let msg = handmade_authenticate(&[], &[], &user);
    match provider.step(&neg_token_resp(&msg), &mut state).await {
        Err(AuthError::LogonFailure(reason)) => {
            assert!(reason.contains("without NT response"), "reason: {reason}");
        }
        other => panic!("expected LogonFailure, got {other:?}"),
    }
}

#[tokio::test]
async fn authenticate_before_challenge_is_rejected() {
    let provider = provider(true);
    let mut state = AuthState::new();
    let anon = handmade_authenticate(&[], &[], &[]);
    assert!(provider.step(&anon, &mut state).await.is_err());
}
