mod serial;
mod ssh;
mod telnet;
mod transport;

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::AppState;
use transport::Transport;

const MAX_INPUT_CHUNK: usize = 64 * 1024;
const MAX_TERMINAL_DIMENSION: u16 = 1_000;
const MAX_CONSOLE_SESSIONS: usize = 16;
/// How long a polite transport close may take before the pump is dropped.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Ssh,
    Telnet,
    Serial,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ConsoleEvent {
    Data {
        b64: String,
    },
    Status {
        state: String,
        message: String,
    },
    HostKey {
        host: String,
        port: u16,
        fingerprint: String,
        algorithm: String,
        #[serde(rename = "keyB64")]
        key_b64: String,
    },
    Closed {
        reason: String,
        /// Whether the peer went away unexpectedly. A clean logout or a
        /// caller-initiated close is not worth offering a reconnect for.
        recoverable: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum SshAuth {
    Password {
        password: String,
    },
    Key {
        private_key: String,
        passphrase: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ConnectParams {
    Ssh {
        host: String,
        port: u16,
        username: String,
        auth: SshAuth,
        legacy_algos: bool,
    },
    Telnet {
        host: String,
        port: u16,
    },
    Serial {
        port: String,
        baud: u32,
        data_bits: u8,
        parity: String,
        stop_bits: u8,
        flow_control: String,
    },
}

enum SessionCommand {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

pub struct ConsoleSession {
    tx: mpsc::Sender<SessionCommand>,
    task: tokio::task::JoinHandle<()>,
    pub kind: TransportKind,
    pub label: String,
}

pub type ConsoleSessions = Arc<Mutex<HashMap<String, ConsoleSession>>>;

/// Registers an already-connected transport and starts its bidirectional pump.
/// Transport-specific connect commands call this after negotiation/authentication.
pub async fn register_transport<T>(
    session_id: String,
    kind: TransportKind,
    label: String,
    transport: T,
    on_event: Channel<ConsoleEvent>,
    sessions: ConsoleSessions,
) -> Result<(), String>
where
    T: Transport,
{
    register_transport_with_sink(
        session_id,
        kind,
        label,
        transport,
        move |event| on_event.send(event).is_ok(),
        sessions,
    )
    .await
}

async fn register_transport_with_sink<T, F>(
    session_id: String,
    kind: TransportKind,
    label: String,
    transport: T,
    send_event: F,
    sessions: ConsoleSessions,
) -> Result<(), String>
where
    T: Transport,
    F: Fn(ConsoleEvent) -> bool + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(128);
    let (start_tx, start_rx) = oneshot::channel();
    let task_session_id = session_id.clone();
    let task_sessions = sessions.clone();

    let task = tokio::spawn(async move {
        if start_rx.await.is_err() {
            return;
        }

        run_session(transport, rx, &send_event).await;
        task_sessions.lock().await.remove(&task_session_id);
    });

    let mut registry = sessions.lock().await;
    if registry.contains_key(&session_id) {
        task.abort();
        return Err(format!("Console session '{session_id}' already exists."));
    }
    registry.insert(
        session_id,
        ConsoleSession {
            tx,
            task,
            kind,
            label,
        },
    );
    drop(registry);

    // The start barrier prevents a transport that closes immediately from
    // racing registry insertion and leaving behind a stale session entry.
    let _ = start_tx.send(());
    Ok(())
}

async fn run_session<T, F>(
    mut transport: T,
    mut commands: mpsc::Receiver<SessionCommand>,
    send_event: &F,
) where
    T: Transport,
    F: Fn(ConsoleEvent) -> bool,
{
    let mut read_buffer = vec![0_u8; 16 * 1024];

    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(SessionCommand::Data(bytes)) => {
                        if let Err(error) = transport.write_all(&bytes).await {
                            send_event(ConsoleEvent::Closed {
                                reason: format!("Console write failed: {error}"),
                                recoverable: true,
                            });
                            break;
                        }
                    }
                    Some(SessionCommand::Resize { cols, rows }) => {
                        if let Err(error) = transport.resize(cols, rows).await {
                            if !send_event(ConsoleEvent::Status {
                                state: "warning".into(),
                                message: format!("Terminal resize was not applied: {error}"),
                            }) {
                                break;
                            }
                        }
                    }
                    Some(SessionCommand::Close) => {
                        // Close politely so SSH sends a disconnect message and
                        // Telnet a FIN, rather than the peer seeing the socket
                        // vanish. The caller already moved this session to a
                        // disconnected state, so no Closed event is emitted.
                        let _ = transport.shutdown().await;
                        break;
                    }
                    None => {
                        let _ = transport.shutdown().await;
                        send_event(ConsoleEvent::Closed {
                            reason: "The console controller closed.".into(),
                            recoverable: false,
                        });
                        break;
                    }
                }
            }
            result = transport.read(&mut read_buffer) => {
                match result {
                    Ok(0) => {
                        // An idle timeout and a typed `exit` both arrive as a
                        // clean end-of-stream — SSH gives nothing to tell them
                        // apart — so every remote close offers a reconnect. Only
                        // a disconnect the user asked for ends a session for good.
                        send_event(ConsoleEvent::Closed {
                            reason: "The remote console closed the connection.".into(),
                            recoverable: true,
                        });
                        break;
                    }
                    Ok(length) => {
                        if !send_event(ConsoleEvent::Data {
                            b64: BASE64.encode(&read_buffer[..length]),
                        }) {
                            break;
                        }
                    }
                    Err(error) => {
                        send_event(ConsoleEvent::Closed {
                            reason: format!("Console read failed: {error}"),
                            recoverable: true,
                        });
                        break;
                    }
                }
            }
        }
    }
}

fn validate_terminal_size(cols: u16, rows: u16) -> Result<(), String> {
    if cols == 0 || rows == 0 || cols > MAX_TERMINAL_DIMENSION || rows > MAX_TERMINAL_DIMENSION {
        return Err(format!(
            "Terminal size must be between 1 and {MAX_TERMINAL_DIMENSION}."
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn console_connect(
    params: ConnectParams,
    cols: u16,
    rows: u16,
    on_event: Channel<ConsoleEvent>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    validate_terminal_size(cols, rows)?;
    if state.console_sessions.lock().await.len() >= MAX_CONSOLE_SESSIONS {
        return Err(format!(
            "NetPulse supports at most {MAX_CONSOLE_SESSIONS} simultaneous console sessions."
        ));
    }

    let session_number = state
        .console_next_session_id
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let session_id = format!("console-{session_number}");

    match params {
        ConnectParams::Ssh {
            host,
            port,
            username,
            auth,
            legacy_algos,
        } => {
            let known_hosts = app
                .path()
                .app_data_dir()
                .map_err(|error| {
                    format!("Could not resolve the NetPulse app-data directory: {error}")
                })?
                .join("known_hosts");
            let transport = ssh::connect(
                &host,
                port,
                &username,
                auth,
                legacy_algos,
                cols,
                rows,
                &known_hosts,
                on_event.clone(),
            )
            .await?;
            register_transport(
                session_id.clone(),
                TransportKind::Ssh,
                format!("{username}@{host}:{port}"),
                transport,
                on_event,
                state.console_sessions.clone(),
            )
            .await?;
        }
        ConnectParams::Telnet { host, port } => {
            let transport = telnet::connect(&host, port, cols, rows, &on_event).await?;
            register_transport(
                session_id.clone(),
                TransportKind::Telnet,
                format!("{host}:{port}"),
                transport,
                on_event,
                state.console_sessions.clone(),
            )
            .await?;
        }
        ConnectParams::Serial {
            port,
            baud,
            data_bits,
            parity,
            stop_bits,
            flow_control,
        } => {
            let transport = serial::connect(
                &port,
                baud,
                data_bits,
                &parity,
                stop_bits,
                &flow_control,
                &on_event,
            )?;
            register_transport(
                session_id.clone(),
                TransportKind::Serial,
                format!("{port} @ {baud}"),
                transport,
                on_event,
                state.console_sessions.clone(),
            )
            .await?;
        }
    }

    Ok(session_id)
}

#[tauri::command]
pub async fn serial_list_ports() -> Result<Vec<serial::SerialPortEntry>, String> {
    serial::list_ports().await
}

#[tauri::command]
pub async fn console_known_hosts_trust(
    host: String,
    port: u16,
    fingerprint: String,
    key_b64: String,
    app: AppHandle,
) -> Result<(), String> {
    crate::commands::validation::validate_host(host.trim())?;
    let key = russh::keys::parse_public_key_base64(&key_b64)
        .map_err(|error| format!("The SSH host key could not be decoded: {error}"))?;
    let actual_fingerprint = key.fingerprint(Default::default()).to_string();
    if actual_fingerprint != fingerprint {
        return Err("The SSH host key fingerprint changed before it could be trusted.".into());
    }

    let path = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not resolve the NetPulse app-data directory: {error}"))?
        .join("known_hosts");
    russh::keys::known_hosts::learn_known_hosts_path(host.trim(), port, &key, path)
        .map_err(|error| format!("Could not save the SSH host key: {error}"))
}


async fn session_sender(
    sessions: &ConsoleSessions,
    session_id: &str,
) -> Result<mpsc::Sender<SessionCommand>, String> {
    sessions
        .lock()
        .await
        .get(session_id)
        .map(|session| session.tx.clone())
        .ok_or_else(|| format!("Console session '{session_id}' was not found."))
}

#[tauri::command]
pub async fn console_send(
    session_id: String,
    b64: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|_| "Console input is not valid base64.".to_string())?;
    if bytes.len() > MAX_INPUT_CHUNK {
        return Err(format!(
            "Console input exceeds the {MAX_INPUT_CHUNK}-byte limit."
        ));
    }

    session_sender(&state.console_sessions, &session_id)
        .await?
        .send(SessionCommand::Data(bytes))
        .await
        .map_err(|_| "The console session is already closed.".to_string())
}

#[tauri::command]
pub async fn console_resize(
    session_id: String,
    cols: u16,
    rows: u16,
    state: State<'_, AppState>,
) -> Result<(), String> {
    validate_terminal_size(cols, rows)?;

    session_sender(&state.console_sessions, &session_id)
        .await?
        .send(SessionCommand::Resize { cols, rows })
        .await
        .map_err(|_| "The console session is already closed.".to_string())
}

/// Closes a session's transport politely, falling back to dropping it outright.
///
/// The pump owns the transport, so the close has to happen there. If it does
/// not finish within `grace` — a wedged OS call, an unresponsive peer — the
/// task is aborted, which drops the transport and releases the socket or port.
async fn close_session(session: ConsoleSession, grace: std::time::Duration) {
    let ConsoleSession { tx, task, .. } = session;
    let abort = task.abort_handle();

    if tx.send(SessionCommand::Close).await.is_ok() {
        drop(tx);
        if tokio::time::timeout(grace, task).await.is_ok() {
            return;
        }
    }

    abort.abort();
}

#[tauri::command]
pub async fn console_disconnect(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Remove first so the lock is released before awaiting the pump, which
    // takes the same lock to deregister itself when it finishes.
    let session = state
        .console_sessions
        .lock()
        .await
        .remove(&session_id)
        .ok_or_else(|| format!("Console session '{session_id}' was not found."))?;

    close_session(session, SHUTDOWN_GRACE).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use tokio::time::{timeout, Duration};

    #[derive(Default)]
    struct TestTransport {
        reads: VecDeque<Vec<u8>>,
        writes: Arc<StdMutex<Vec<Vec<u8>>>>,
        closed: bool,
        shutdowns: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Transport for TestTransport {
        fn shutdown(&mut self) -> impl std::future::Future<Output = Result<(), String>> + Send {
            self.shutdowns
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Ok(()) }
        }

        fn read<'a>(
            &'a mut self,
            buffer: &'a mut [u8],
        ) -> impl std::future::Future<Output = Result<usize, String>> + Send + 'a {
            async move {
                if let Some(bytes) = self.reads.pop_front() {
                    let length = bytes.len().min(buffer.len());
                    buffer[..length].copy_from_slice(&bytes[..length]);
                    return Ok(length);
                }
                if self.closed {
                    return Ok(0);
                }
                std::future::pending().await
            }
        }

        fn write_all<'a>(
            &'a mut self,
            bytes: &'a [u8],
        ) -> impl std::future::Future<Output = Result<(), String>> + Send + 'a {
            async move {
                self.writes.lock().unwrap().push(bytes.to_vec());
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn session_pump_preserves_arbitrary_bytes_in_both_directions() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let writes = Arc::new(StdMutex::new(Vec::new()));
        let outbound = vec![0x00, 0xff, 0xf0, 0x9f, 0x92, 0xa1];
        let transport = TestTransport {
            reads: VecDeque::from([outbound.clone()]),
            writes: writes.clone(),
            ..Default::default()
        };
        let events = Arc::new(StdMutex::new(Vec::new()));
        let captured = events.clone();

        register_transport_with_sink(
            "1".into(),
            TransportKind::Telnet,
            "test".into(),
            transport,
            move |event| {
                captured.lock().unwrap().push(event);
                true
            },
            sessions.clone(),
        )
        .await
        .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                if !events.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let ConsoleEvent::Data { b64 } = &events.lock().unwrap()[0] else {
            panic!("expected a data event");
        };
        assert_eq!(BASE64.decode(b64).unwrap(), outbound);

        let input = vec![0x0d, 0xff, 0x00];
        session_sender(&sessions, "1")
            .await
            .unwrap()
            .send(SessionCommand::Data(input.clone()))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while writes.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(writes.lock().unwrap()[0], input);
    }

    #[tokio::test]
    async fn closed_transport_removes_the_registry_entry() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let transport = TestTransport {
            closed: true,
            ..Default::default()
        };
        register_transport_with_sink(
            "2".into(),
            TransportKind::Serial,
            "test".into(),
            transport,
            |_| true,
            sessions.clone(),
        )
        .await
        .unwrap();

        assert!(sessions.lock().await.contains_key("2"));
        timeout(Duration::from_secs(1), async {
            while sessions.lock().await.contains_key("2") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn disconnect_closes_the_transport_politely_without_a_closed_event() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let events = Arc::new(StdMutex::new(Vec::new()));
        let captured = events.clone();

        register_transport_with_sink(
            "3".into(),
            TransportKind::Ssh,
            "test".into(),
            TestTransport {
                shutdowns: shutdowns.clone(),
                ..Default::default()
            },
            move |event| {
                captured.lock().unwrap().push(event);
                true
            },
            sessions.clone(),
        )
        .await
        .unwrap();

        let session = sessions.lock().await.remove("3").expect("session registered");
        close_session(session, Duration::from_secs(5)).await;

        // The transport was shut down rather than dropped mid-flight, and the
        // caller is not told about a disconnect it asked for.
        assert_eq!(shutdowns.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            !events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, ConsoleEvent::Closed { .. })),
            "a caller-initiated disconnect should not emit a Closed event"
        );
    }

    #[tokio::test]
    async fn a_remote_close_is_offered_as_recoverable() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let events = Arc::new(StdMutex::new(Vec::new()));
        let captured = events.clone();

        register_transport_with_sink(
            "4".into(),
            TransportKind::Ssh,
            "test".into(),
            TestTransport {
                closed: true,
                ..Default::default()
            },
            move |event| {
                captured.lock().unwrap().push(event);
                true
            },
            sessions.clone(),
        )
        .await
        .unwrap();

        timeout(Duration::from_secs(1), async {
            while events.lock().unwrap().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let ConsoleEvent::Closed { recoverable, .. } = &events.lock().unwrap()[0] else {
            panic!("expected a closed event");
        };
        assert!(
            recoverable,
            "an idle timeout reaches us as end-of-stream, so it must offer a reconnect"
        );
    }

    #[tokio::test]
    async fn multiple_sessions_keep_their_input_isolated() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let first_writes = Arc::new(StdMutex::new(Vec::new()));
        let second_writes = Arc::new(StdMutex::new(Vec::new()));

        for (id, writes) in [
            ("first", first_writes.clone()),
            ("second", second_writes.clone()),
        ] {
            register_transport_with_sink(
                id.into(),
                TransportKind::Telnet,
                id.into(),
                TestTransport {
                    writes,
                    ..Default::default()
                },
                |_| true,
                sessions.clone(),
            )
            .await
            .unwrap();
        }

        session_sender(&sessions, "first")
            .await
            .unwrap()
            .send(SessionCommand::Data(b"alpha".to_vec()))
            .await
            .unwrap();
        session_sender(&sessions, "second")
            .await
            .unwrap()
            .send(SessionCommand::Data(b"beta".to_vec()))
            .await
            .unwrap();

        timeout(Duration::from_secs(1), async {
            while first_writes.lock().unwrap().is_empty()
                || second_writes.lock().unwrap().is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert_eq!(
            first_writes.lock().unwrap().as_slice(),
            &[b"alpha".to_vec()]
        );
        assert_eq!(
            second_writes.lock().unwrap().as_slice(),
            &[b"beta".to_vec()]
        );
    }
}
