//! RSSMB authentication — NTLM acceptor via sspi, SPNEGO, credential store.
//!
//! The auth layer is a multi-round acceptor conversation. SMB SESSION_SETUP
//! exchanges security tokens over multiple messages (STATUS_MORE_PROCESSING_REQUIRED),
//! and the session key is exported at the end for signing/encryption.
//!
//! We use the raw `sspi::ntlm::Ntlm` SSP directly and handle SPNEGO
//! wrapping/unwrapping ourselves, because the `Negotiate` SSP doesn't
//! correctly unwrap SPNEGO negTokenResp on the second round.

use thiserror::Error;

pub mod credentials;
pub mod ntlm_mic;
pub mod ntlmv2;
pub mod spnego;

pub use credentials::CredentialStore;

use sspi::{
    BufferType, DataRepresentation,
    SecurityBuffer, SecurityStatus,
    ServerRequestFlags, Sspi, SspiEx, SspiImpl,
    ntlm::Ntlm,
};

/// Authentication state during a multi-round exchange.
pub struct AuthState {
    /// The sspi acceptor (raw NTLM SSP)
    ssp: Option<Ntlm>,
    /// Whether this is the first round
    first_round: bool,
    /// The session key exported on completion
    session_key: Option<Vec<u8>>,
    /// Whether auth has already completed (to handle SPNEGO's final round)
    auth_completed: bool,
    /// The guest identity from the completed auth
    completed_identity: Option<Identity>,
    /// ServerChallenge we sent in the CHALLENGE message, for our own
    /// NTLMv2 proof check on the AUTHENTICATE leg.
    server_challenge: Option<[u8; 8]>,
    /// Set only after our own NTLMv2 proof check succeeded in this
    /// conversation. Required for any non-guest completion.
    proof_verified: bool,
    /// The client sent bare NTLMSSP (no SPNEGO), as Linux cifs.ko does with
    /// sec=ntlmssp. Replies must then also be bare NTLMSSP.
    raw_ntlmssp: bool,
    /// DER-encoded mechTypes from the client's SPNEGO negTokenInit, saved
    /// for the mechListMIC in the final accept-completed response.
    mech_types: Option<Vec<u8>>,
    /// NTLM negotiate flags from the AUTHENTICATE message, for MIC signing.
    ntlm_neg_flags: u32,
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("first_round", &self.first_round)
            .field("has_session_key", &self.session_key.is_some())
            .field("auth_completed", &self.auth_completed)
            .finish()
    }
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            ssp: None,
            first_round: true,
            session_key: None,
            auth_completed: false,
            completed_identity: None,
            server_challenge: None,
            proof_verified: false,
            raw_ntlmssp: false,
            mech_types: None,
            ntlm_neg_flags: 0,
        }
    }

    /// Whether replies in this conversation should be SPNEGO-wrapped.
    pub fn uses_spnego(&self) -> bool {
        !self.raw_ntlmssp
    }

    fn wrap(&self, ntlm: &[u8]) -> Vec<u8> {
        if self.raw_ntlmssp {
            ntlm.to_vec()
        } else {
            spnego::wrap_ntlm_response(ntlm)
        }
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of one step of the authentication conversation.
#[derive(Debug)]
pub enum AuthStep {
    /// Send this output token to the client and wait for the next input.
    Continue { output_token: Vec<u8> },
    /// Authentication successful — the session key is available.
    Complete {
        output_token: Vec<u8>,
        session_key: Vec<u8>,
        identity: Identity,
    },
    /// Authentication failed.
    Reject { reason: AuthError },
}

/// Authenticated identity.
#[derive(Debug, Clone)]
pub struct Identity {
    pub username: String,
    pub domain: String,
    pub is_guest: bool,
}

/// Authentication error.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("logon failure: {0}")]
    LogonFailure(String),
    #[error("no more processing required but not complete")]
    NotComplete,
    #[error("SPNEGO parse error: {0}")]
    SpnegoError(String),
    #[error("sspi error: {0}")]
    SspiError(String),
    #[error("no credentials provided")]
    NoCredentials,
    #[error("unsupported mechanism")]
    UnsupportedMechanism,
}

/// The authentication provider trait — a multi-round acceptor conversation.
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    async fn step(
        &self,
        input_token: &[u8],
        state: &mut AuthState,
    ) -> Result<AuthStep, AuthError>;
}

/// NTLM authentication provider using the raw `sspi::ntlm::Ntlm` SSP.
///
/// We handle SPNEGO unwrapping ourselves:
/// - Incoming: extract NTLMSSP token from SPNEGO wrapper via `spnego::extract_ntlm_token`
/// - Outgoing: wrap NTLMSSP response in SPNEGO negTokenResp via `spnego::wrap_ntlm_response`
/// This avoids the sspi `Negotiate` SSP's bug where it doesn't correctly
/// unwrap SPNEGO negTokenResp on the second round.
///
/// Server-side credentials (identities) are wired into the Ntlm SSP via
/// `SspiEx::custom_set_auth_identities` so the acceptor can verify NTLMv2
/// proofs against real user accounts. If the identities list is empty, the
/// acceptor operates in anonymous/guest-only mode.
pub struct NtlmAuthProvider {
    identities: Vec<sspi::AuthIdentity>,
    /// Whether guest access is enabled at the server level.
    guest_access: bool,
}

impl NtlmAuthProvider {
    pub fn from_store(_store: &CredentialStore) -> Self {
        Self { identities: vec![], guest_access: false }
    }

    pub fn with_identities(identities: Vec<sspi::AuthIdentity>) -> Self {
        Self { identities, guest_access: false }
    }

    pub fn with_identities_and_guest(
        identities: Vec<sspi::AuthIdentity>,
        guest_access: bool,
    ) -> Self {
        Self { identities, guest_access }
    }
}

#[async_trait::async_trait]
impl AuthProvider for NtlmAuthProvider {
    async fn step(
        &self,
        input_token: &[u8],
        state: &mut AuthState,
    ) -> Result<AuthStep, AuthError> {
        // If auth already completed, this is the final SPNEGO round
        // (negTokenResp with the client's mechListMIC). Verify the
        // client's MIC when NTLM signing was negotiated (RFC 4178 §5).
        if state.auth_completed {
            let identity = state.completed_identity.clone().ok_or_else(|| {
                AuthError::LogonFailure("internal state error: completed identity missing".into())
            })?;
            let session_key = state.session_key.clone().ok_or_else(|| {
                AuthError::LogonFailure("internal state error: session key missing".into())
            })?;

            // Verify the client's mechListMIC if signing was negotiated.
            // For raw NTLMSSP (no SPNEGO), there is no MIC to verify.
            if state.uses_spnego() && ntlm_mic::supported(state.ntlm_neg_flags) {
                let client_mic = spnego::extract_mech_list_mic(input_token);
                if let Some(mic) = client_mic {
                    let mech_types = state.mech_types.as_deref().unwrap_or(&[]);
                    if !ntlm_mic::verify_client(
                        &session_key,
                        state.ntlm_neg_flags,
                        mech_types,
                        &mic,
                    ) {
                        tracing::warn!("mechListMIC verification failed — rejecting");
                        return Err(AuthError::LogonFailure("mechListMIC mismatch".into()));
                    }
                    tracing::debug!("mechListMIC verified successfully");
                } else {
                    // Signing was negotiated but no MIC was provided.
                    // This is a protocol violation — the client must send
                    // its mechListMIC when the server sent one.
                    tracing::warn!("signing negotiated but client sent no mechListMIC — rejecting");
                    return Err(AuthError::LogonFailure("missing mechListMIC".into()));
                }
            }

            return Ok(AuthStep::Complete {
                output_token: vec![],
                session_key,
                identity,
            });
        }

        // Initialize the NTLM SSP on the first call
        if state.first_round {
            state.first_round = false;

            // Candidate identities are applied after the AUTHENTICATE message
            // is parsed (see below); setting them here would also pre-seed
            // `identity` and they are discarded by sspi on that leg anyway.
            state.ssp = Some(Ntlm::new());
        }

        let ssp = state.ssp.as_mut().ok_or(AuthError::NotComplete)?;

        // Framing is decided by the client's first token and then fixed.
        if state.server_challenge.is_none() {
            state.raw_ntlmssp = input_token.starts_with(b"NTLMSSP\0");
            // Save the mechTypes from the SPNEGO negTokenInit for the
            // mechListMIC in the final accept-completed response.
            if !state.raw_ntlmssp {
                state.mech_types = spnego::extract_mech_types(input_token);
            }
        }

        // Unwrap SPNEGO to get the raw NTLMSSP token
        let ntlm_token = spnego::extract_ntlm_token(input_token)
            .unwrap_or_else(|_| input_token.to_vec());

        // Anonymous AUTHENTICATE (MS-NLMP 3.2.5.1.2) is recognised
        // structurally — never from sspi error text. It never reaches the
        // proof verifier: either it becomes a guest session (when the server
        // allows guests) or it is a logon failure.
        if let Some(summary) = spnego::parse_authenticate(&ntlm_token) {
            if summary.is_anonymous() {
                // Only valid as the reply to our CHALLENGE.
                if state.server_challenge.is_none() {
                    return Err(AuthError::LogonFailure("AUTHENTICATE before CHALLENGE".into()));
                }
                if !self.guest_access {
                    return Err(AuthError::LogonFailure("anonymous logon disabled".into()));
                }
                tracing::debug!("NTLM anonymous AUTHENTICATE → guest session");
                let identity = Identity {
                    username: "guest".to_string(),
                    domain: String::new(),
                    is_guest: true,
                };
                state.auth_completed = true;
                state.completed_identity = Some(identity.clone());
                return Ok(AuthStep::Complete {
                    output_token: vec![],
                    session_key: vec![],
                    identity,
                });
            }
        }

        // Pass the raw NTLMSSP token to the NTLM SSP
        let mut input = [SecurityBuffer::new(ntlm_token, BufferType::Token)];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut cred_handle: Option<_> = None;

        let builder = ssp
            .accept_security_context()
            .with_credentials_handle(&mut cred_handle)
            .with_context_requirements(ServerRequestFlags::empty())
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);

        // Any acceptor error is a logon failure. No error ever becomes guest.
        let result = ssp
            .accept_security_context_impl(builder)
            .and_then(|mut gen| gen.resolve_to_result())
            .map_err(|e| {
                tracing::debug!("NTLM accept failed: {e}");
                AuthError::LogonFailure(e.to_string())
            })?;

        let ntlm_output = output[0].buffer.clone();

        if result.status == SecurityStatus::ContinueNeeded {
            state.server_challenge = ntlmv2::server_challenge(&ntlm_output);
            if state.server_challenge.is_none() {
                return Err(AuthError::SspiError("CHALLENGE message missing server challenge".into()));
            }
        }

        let mut status = result.status;
        if status == SecurityStatus::CompleteNeeded {
            // The AUTHENTICATE message has been parsed. sspi's accept path
            // resets `allowed_identities` from the (absent) credentials
            // handle on this leg, so the candidate list must be re-applied
            // here. `identity` already holds the wire user/domain and is not
            // overwritten. With no configured users there is nothing to
            // verify against → logon failure.
            //
            // sspi verifies the proof as (wire user/domain, candidate
            // password). Passing every configured account would let a client
            // claim "alice" while proving knowledge of bob's password, so the
            // candidate list is narrowed to the single account whose name
            // matches the claimed user.
            let wire_user = ssp
                .query_context_names()
                .map(|n| account_name(&n.username))
                .map_err(|e| AuthError::LogonFailure(format!("no user in AUTHENTICATE: {e}")))?;
            let candidate = self
                .identities
                .iter()
                .find(|id| account_name(&id.username).eq_ignore_ascii_case(&wire_user))
                .cloned()
                .ok_or_else(|| AuthError::LogonFailure(format!("unknown user {wire_user:?}")))?;

            // The pinned sspi only rejects a wrong password through the
            // optional MIC; without a MIC it accepts anything. Check the
            // NTLMv2 proof ourselves first — this is the authoritative check.
            let challenge = state
                .server_challenge
                .ok_or_else(|| AuthError::LogonFailure("AUTHENTICATE before CHALLENGE".into()))?;
            let fields = ntlmv2::parse_authenticate_fields(&input[0].buffer)
                .ok_or_else(|| AuthError::LogonFailure("malformed AUTHENTICATE".into()))?;
            // Both parsers must agree on who is logging in.
            let parsed_user = fields.user();
            if account_name_str(&parsed_user) != wire_user {
                return Err(AuthError::LogonFailure("AUTHENTICATE user mismatch".into()));
            }
            let password = candidate.password.as_ref().to_string();
            if !ntlmv2::verify(&fields, &password, &challenge) {
                tracing::debug!(user = %wire_user, "NTLMv2 proof mismatch");
                return Err(AuthError::LogonFailure("NTLMv2 proof mismatch".into()));
            }
            state.proof_verified = true;

            // Save the negotiate flags for the mechListMIC computation.
            state.ntlm_neg_flags = fields.neg_flags;

            ssp.custom_set_auth_identities(vec![candidate])
                .map_err(|e| AuthError::SspiError(format!("set_auth_identities: {e}")))?;
            // complete_auth_token verifies the NTLMv2 proof against the
            // candidates (wrong password → error here).
            status = ssp.complete_auth_token(&mut []).map_err(|e| {
                tracing::debug!("NTLM proof verification failed: {e}");
                AuthError::LogonFailure(e.to_string())
            })?;
        }

        match status {
            SecurityStatus::ContinueNeeded => {
                // Wrap the NTLM challenge in SPNEGO negTokenResp
                let wrapped = state.wrap(&ntlm_output);
                Ok(AuthStep::Continue { output_token: wrapped })
            }
            SecurityStatus::Ok | SecurityStatus::CompleteNeeded if !state.proof_verified => {
                Err(AuthError::LogonFailure("acceptor completed without a verified proof".into()))
            }
            SecurityStatus::Ok | SecurityStatus::CompleteNeeded => {
                let key_info = ssp
                    .query_context_session_key()
                    .map_err(|e| AuthError::SspiError(format!("session_key: {e}")))?;
                let session_key = key_info.session_key.as_ref().clone();

                // Authenticated account name. Fail closed rather than invent
                // a principal — valid_users checks depend on it.
                let username = ssp
                    .query_context_names()
                    .map(|names| account_name(&names.username))
                    .map_err(|e| AuthError::SspiError(format!("query_context_names: {e}")))?;

                let identity = Identity {
                    username,
                    domain: String::new(),
                    is_guest: false,
                };

                state.session_key = Some(session_key.clone());
                state.auth_completed = true;
                state.completed_identity = Some(identity.clone());

                // Verify the client's mechListMIC if it accompanies the
                // AUTHENTICATE token (RFC 4178 §5). Some clients send the
                // MIC in the same negTokenResp as the AUTHENTICATE; others
                // send it in a separate follow-up round that lands in the
                // auth_completed branch. Verify in both places.
                if state.uses_spnego() && ntlm_mic::supported(state.ntlm_neg_flags) {
                    if let Some(client_mic) = spnego::extract_mech_list_mic(input_token) {
                        let mech_types = state.mech_types.as_deref().unwrap_or(&[]);
                        if !ntlm_mic::verify_client(
                            &session_key,
                            state.ntlm_neg_flags,
                            mech_types,
                            &client_mic,
                        ) {
                            tracing::warn!("mechListMIC verification failed on AUTHENTICATE leg");
                            return Err(AuthError::LogonFailure("mechListMIC mismatch".into()));
                        }
                        tracing::debug!("mechListMIC verified on AUTHENTICATE leg");
                    }
                    // If no MIC is present on this leg, it may arrive in the
                    // next SPNEGO round (auth_completed branch). Don't reject
                    // yet — the client may send it separately.
                }

                // NTLM's final leg has no server token. For SPNEGO clients
                // that negotiated NTLMSSP signing (Samba/Windows), the final
                // negTokenResp must carry a mechListMIC — a signature of the
                // mechTypes list with the session key — or the client rejects
                // the response (Samba: NT_STATUS_INVALID_NETWORK_RESPONSE).
                let output_token = if ntlm_output.is_empty() {
                    if state.uses_spnego() && ntlm_mic::supported(state.ntlm_neg_flags) {
                        let mic = state.mech_types.as_deref().map(|mt| {
                            ntlm_mic::sign(
                                &session_key,
                                state.ntlm_neg_flags,
                                ntlm_mic::Direction::ServerToClient,
                                0,
                                mt,
                            )
                        });
                        spnego::wrap_accept_completed(mic.as_ref().map(|m| m.as_slice()))
                    } else if state.uses_spnego() {
                        // No signing negotiated — simple accept-completed.
                        spnego::wrap_accept_completed(None)
                    } else {
                        vec![]
                    }
                } else {
                    state.wrap(&ntlm_output)
                };
                Ok(AuthStep::Complete {
                    output_token,
                    session_key,
                    identity,
                })
            }
            other => {
                Err(AuthError::SspiError(format!("unexpected status: {other:?}")))
            }
        }
    }
}

/// The bare account name of a username (drops any NetBIOS domain / UPN suffix).
fn account_name(u: &sspi::Username) -> String {
    match u.parts() {
        sspi::UsernameParts::DownLevelLogonName(d) => d.account_name().to_string(),
        sspi::UsernameParts::UserPrincipalName(p) => p.account_name().to_string(),
    }
}

/// `account_name` for a raw wire string, via the same parser.
fn account_name_str(s: &str) -> String {
    sspi::Username::parse(s)
        .map(|u| account_name(&u))
        .unwrap_or_else(|_| s.to_string())
}

/// Guest authentication provider — always succeeds with guest identity.
pub struct GuestAuthProvider;

#[async_trait::async_trait]
impl AuthProvider for GuestAuthProvider {
    async fn step(
        &self,
        _input_token: &[u8],
        _state: &mut AuthState,
    ) -> Result<AuthStep, AuthError> {
        Ok(AuthStep::Complete {
            output_token: vec![],
            session_key: vec![],
            identity: Identity {
                username: "guest".to_string(),
                domain: "".to_string(),
                is_guest: true,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_guest_auth() {
        let provider = GuestAuthProvider;
        let mut state = AuthState::new();

        let result = provider.step(&[], &mut state).await.unwrap();
        match result {
            AuthStep::Complete { identity, .. } => {
                assert_eq!(identity.username, "guest");
                assert!(identity.is_guest);
            }
            _ => panic!("expected Complete"),
        }
    }
}
