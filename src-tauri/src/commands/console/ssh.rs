use std::borrow::Cow;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyBase64};
use russh::{ChannelMsg, Disconnect, Preferred};
use tauri::ipc::Channel;
use zeroize::Zeroize;

use super::transport::Transport;
use super::{ConsoleEvent, SshAuth};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const AUTH_TIMEOUT: Duration = Duration::from_secs(20);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
enum HostKeyFailure {
    Unknown,
    Mismatch,
}

struct SshHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    on_event: Channel<ConsoleEvent>,
    failure: Arc<Mutex<Option<HostKeyFailure>>>,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        let known = russh::keys::known_hosts::known_host_keys_path(
            &self.host,
            self.port,
            &self.known_hosts,
        )
        .unwrap_or_default();

        if known.iter().any(|(_, key)| key == server_public_key) {
            return Ok(true);
        }

        if known.is_empty() {
            *self.failure.lock().unwrap() = Some(HostKeyFailure::Unknown);
            let _ = self.on_event.send(ConsoleEvent::HostKey {
                host: self.host.clone(),
                port: self.port,
                fingerprint,
                algorithm: server_public_key.algorithm().as_str().to_string(),
                key_b64: server_public_key.public_key_base64(),
            });
        } else {
            *self.failure.lock().unwrap() = Some(HostKeyFailure::Mismatch);
            let _ = self.on_event.send(ConsoleEvent::Status {
                state: "danger".into(),
                message: format!(
                    "SSH host key mismatch for {}:{} (presented {}). Connection refused.",
                    self.host, self.port, fingerprint
                ),
            });
        }
        Ok(false)
    }
}

pub struct SshTransport {
    channel: russh::Channel<client::Msg>,
    session: client::Handle<SshHandler>,
    pending: VecDeque<u8>,
}

impl Transport for SshTransport {
    fn read<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, String>> + Send + 'a {
        async move {
            if !self.pending.is_empty() {
                return Ok(drain_pending(&mut self.pending, buffer));
            }

            loop {
                match self.channel.wait().await {
                    Some(ChannelMsg::Data { data })
                    | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        self.pending.extend(data);
                        return Ok(drain_pending(&mut self.pending, buffer));
                    }
                    Some(ChannelMsg::Eof)
                    | Some(ChannelMsg::Close)
                    | Some(ChannelMsg::ExitStatus { .. })
                    | None => return Ok(0),
                    Some(_) => {}
                }
            }
        }
    }

    fn write_all<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> impl std::future::Future<Output = Result<(), String>> + Send + 'a {
        async move {
            self.channel
                .data_bytes(bytes.to_vec())
                .await
                .map_err(|error| format!("SSH write failed: {error}"))
        }
    }

    fn resize(
        &mut self,
        cols: u16,
        rows: u16,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async move {
            self.channel
                .window_change(cols.into(), rows.into(), 0, 0)
                .await
                .map_err(|error| format!("SSH PTY resize failed: {error}"))
        }
    }

    fn shutdown(&mut self) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async move {
            let _ = self.channel.eof().await;
            let _ = self.channel.close().await;
            self.session
                .disconnect(
                    Disconnect::ByApplication,
                    "NetPulse console disconnected",
                    "en",
                )
                .await
                .map_err(|error| format!("SSH disconnect failed: {error}"))
        }
    }
}

fn drain_pending(pending: &mut VecDeque<u8>, buffer: &mut [u8]) -> usize {
    let length = pending.len().min(buffer.len());
    for slot in &mut buffer[..length] {
        *slot = pending.pop_front().unwrap();
    }
    length
}

fn legacy_preferences() -> Preferred {
    let mut preferred = Preferred::default();

    let mut kex = preferred.kex.to_vec();
    for algorithm in [russh::kex::DH_G14_SHA1, russh::kex::DH_G1_SHA1] {
        if !kex.contains(&algorithm) {
            kex.push(algorithm);
        }
    }
    preferred.kex = Cow::Owned(kex);

    let ssh_rsa = russh::keys::Algorithm::Rsa { hash: None };
    let mut keys = preferred.key.to_vec();
    if !keys.contains(&ssh_rsa) {
        keys.push(ssh_rsa);
    }
    preferred.key = Cow::Owned(keys);

    let mut ciphers = preferred.cipher.to_vec();
    for cipher in [
        russh::cipher::AES_128_CBC,
        russh::cipher::AES_192_CBC,
        russh::cipher::AES_256_CBC,
    ] {
        if !ciphers.contains(&cipher) {
            ciphers.push(cipher);
        }
    }
    preferred.cipher = Cow::Owned(ciphers);

    let mut macs = preferred.mac.to_vec();
    if !macs.contains(&russh::mac::HMAC_SHA1) {
        macs.push(russh::mac::HMAC_SHA1);
    }
    preferred.mac = Cow::Owned(macs);
    preferred
}

/// Decodes pasted OpenSSH/PKCS#8 private-key text into a usable key.
///
/// A wrong or missing passphrase surfaces as a generic crypto error, so it is
/// translated into advice the operator can act on.
fn decode_private_key(
    private_key: &str,
    passphrase: Option<&str>,
) -> Result<russh::keys::PrivateKey, String> {
    let passphrase = passphrase.filter(|value| !value.is_empty());
    russh::keys::decode_secret_key(private_key.trim(), passphrase).map_err(|error| {
        if passphrase.is_none() {
            format!(
                "Could not load the SSH private key: {error}. If the key is encrypted, enter its passphrase."
            )
        } else {
            format!("Could not load the SSH private key: {error}. Check the key text and passphrase.")
        }
    })
}

fn describe_connect_error(error: &russh::Error, legacy_algos: bool) -> String {
    let detail = error.to_string();
    let lower = detail.to_lowercase();
    if !legacy_algos
        && (lower.contains("key exchange")
            || lower.contains("no common")
            || lower.contains("algorithm"))
    {
        return format!(
            "SSH algorithm negotiation failed: {detail}. Try 'Allow legacy SSH algorithms' only if this is trusted older equipment."
        );
    }
    format!("SSH connection failed: {detail}")
}

#[allow(clippy::too_many_arguments)]
pub async fn connect(
    host: &str,
    port: u16,
    username: &str,
    auth: SshAuth,
    legacy_algos: bool,
    cols: u16,
    rows: u16,
    known_hosts: &Path,
    on_event: Channel<ConsoleEvent>,
) -> Result<SshTransport, String> {
    let host = host.trim();
    let username = username.trim();
    crate::commands::validation::validate_host(host)?;
    if username.is_empty() {
        return Err("SSH username must not be empty.".into());
    }

    let connect_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    let failure = Arc::new(Mutex::new(None));
    let handler = SshHandler {
        host: connect_host.clone(),
        port,
        known_hosts: known_hosts.to_path_buf(),
        on_event: on_event.clone(),
        failure: failure.clone(),
    };

    let config = client::Config {
        preferred: if legacy_algos {
            legacy_preferences()
        } else {
            Preferred::default()
        },
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    };

    let _ = on_event.send(ConsoleEvent::Status {
        state: "connecting".into(),
        message: format!("Connecting to {connect_host}:{port} over SSH…"),
    });

    let connect_result = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect(Arc::new(config), (connect_host.as_str(), port), handler),
    )
    .await
    .map_err(|_| format!("SSH connection to {connect_host}:{port} timed out."))?;

    let mut session = match connect_result {
        Ok(session) => session,
        Err(error) => {
            let host_key_failure = failure.lock().unwrap().clone();
            return Err(match host_key_failure {
                Some(HostKeyFailure::Unknown) => {
                    "SSH host key approval is required before connecting.".into()
                }
                Some(HostKeyFailure::Mismatch) => {
                    "SSH host key mismatch. Connection refused to protect against interception."
                        .into()
                }
                None => describe_connect_error(&error, legacy_algos),
            });
        }
    };

    let auth_result = match auth {
        SshAuth::Password { mut password } => {
            if password.is_empty() {
                return Err("SSH password must not be empty.".into());
            }
            let result = tokio::time::timeout(
                AUTH_TIMEOUT,
                session.authenticate_password(username, password.clone()),
            )
            .await;
            password.zeroize();
            result
                .map_err(|_| "SSH authentication timed out.".to_string())?
                .map_err(|error| format!("SSH authentication failed: {error}"))?
        }
        SshAuth::Key {
            mut private_key,
            mut passphrase,
        } => {
            if private_key.trim().is_empty() {
                return Err("SSH private key must not be empty.".into());
            }
            // The form supplies the key material itself, so decode it in place.
            // `load_secret_key` takes a filesystem path and would try to open
            // the pasted PEM text as a file name.
            let key = decode_private_key(&private_key, passphrase.as_deref())?;
            private_key.zeroize();
            if let Some(value) = passphrase.as_mut() {
                value.zeroize();
            }
            let hash = session
                .best_supported_rsa_hash()
                .await
                .map_err(|error| format!("Could not negotiate the SSH key signature: {error}"))?
                .flatten();
            tokio::time::timeout(
                AUTH_TIMEOUT,
                session.authenticate_publickey(
                    username,
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                ),
            )
            .await
            .map_err(|_| "SSH authentication timed out.".to_string())?
            .map_err(|error| format!("SSH authentication failed: {error}"))?
        }
    };

    if !auth_result.success() {
        return Err("SSH authentication was rejected. Check the username and credentials.".into());
    }

    let channel = tokio::time::timeout(CHANNEL_TIMEOUT, session.channel_open_session())
        .await
        .map_err(|_| "SSH timed out while opening an interactive channel.".to_string())?
        .map_err(|error| format!("SSH could not open an interactive channel: {error}"))?;
    tokio::time::timeout(
        CHANNEL_TIMEOUT,
        channel.request_pty(true, "xterm-256color", cols.into(), rows.into(), 0, 0, &[]),
    )
    .await
    .map_err(|_| "SSH timed out while requesting a terminal.".to_string())?
    .map_err(|error| format!("SSH server refused the terminal request: {error}"))?;
    tokio::time::timeout(CHANNEL_TIMEOUT, channel.request_shell(true))
        .await
        .map_err(|_| "SSH timed out while starting the remote shell.".to_string())?
        .map_err(|error| format!("SSH server refused the interactive shell: {error}"))?;

    let _ = on_event.send(ConsoleEvent::Status {
        state: "connected".into(),
        message: format!("SSH connected to {connect_host}:{port}."),
    });
    Ok(SshTransport {
        channel,
        session,
        pending: VecDeque::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_bytes_are_drained_without_utf8_conversion() {
        let mut pending = VecDeque::from([0xff, 0x00, 0xf0, 0x9f]);
        let mut buffer = [0_u8; 3];
        assert_eq!(drain_pending(&mut pending, &mut buffer), 3);
        assert_eq!(buffer, [0xff, 0x00, 0xf0]);
        assert_eq!(pending, VecDeque::from([0x9f]));
    }

    /// RFC 8410 §10.3 sample key — a published test vector, not a real secret.
    const RFC8410_ED25519_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";

    #[test]
    fn private_key_auth_accepts_pasted_key_material_not_a_path() {
        // The connect form supplies key text, so decoding must work on the
        // material itself; a path-based loader would fail here.
        let key = decode_private_key(RFC8410_ED25519_KEY, None).expect("pasted key should decode");
        assert_eq!(key.algorithm(), russh::keys::Algorithm::Ed25519);

        // Surrounding whitespace from a copy/paste must not break decoding.
        let padded = format!("\n  {RFC8410_ED25519_KEY}\n");
        assert!(decode_private_key(&padded, None).is_ok());

        // An empty passphrase is treated as "no passphrase", not a wrong one.
        assert!(decode_private_key(RFC8410_ED25519_KEY, Some("")).is_ok());
    }

    #[test]
    fn unreadable_private_key_explains_the_passphrase_option() {
        let error = decode_private_key("not a key", None).unwrap_err();
        assert!(error.contains("passphrase"), "unexpected error: {error}");
    }

    #[test]
    fn legacy_mode_keeps_modern_algorithms_ahead_of_legacy_fallbacks() {
        let defaults = Preferred::default();
        let legacy = legacy_preferences();
        assert!(legacy.kex.starts_with(defaults.kex.as_ref()));
        assert!(legacy.kex.contains(&russh::kex::DH_G14_SHA1));
        assert!(legacy
            .key
            .contains(&russh::keys::Algorithm::Rsa { hash: None }));
        assert!(legacy.cipher.contains(&russh::cipher::AES_128_CBC));
        assert!(legacy.mac.contains(&russh::mac::HMAC_SHA1));
    }
}
