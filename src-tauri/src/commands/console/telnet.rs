use std::collections::VecDeque;
use std::io::ErrorKind;
use std::time::Duration;

use tauri::ipc::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::transport::Transport;
use super::ConsoleEvent;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SUPPRESS_GO_AHEAD: u8 = 3;
const OPT_TERMINAL_TYPE: u8 = 24;
const OPT_NAWS: u8 = 31;
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ParseState {
    #[default]
    Data,
    Iac,
    Will,
    Wont,
    Do,
    Dont,
    SbOption,
    SbData,
    SbIac,
}

struct TelnetCodec {
    state: ParseState,
    sb_option: u8,
    sb_data: Vec<u8>,
    peer_will: [bool; 256],
    local_will: [bool; 256],
    control: VecDeque<u8>,
    cols: u16,
    rows: u16,
}

impl Default for TelnetCodec {
    fn default() -> Self {
        Self {
            state: ParseState::Data,
            sb_option: 0,
            sb_data: Vec::new(),
            peer_will: [false; 256],
            local_will: [false; 256],
            control: VecDeque::new(),
            cols: 0,
            rows: 0,
        }
    }
}

impl TelnetCodec {
    fn new(cols: u16, rows: u16) -> Self {
        let mut codec = Self {
            cols,
            rows,
            ..Default::default()
        };
        codec.queue_command(WILL, OPT_TERMINAL_TYPE);
        codec.local_will[OPT_TERMINAL_TYPE as usize] = true;
        codec.queue_command(WILL, OPT_NAWS);
        codec.local_will[OPT_NAWS as usize] = true;
        codec.queue_command(WILL, OPT_SUPPRESS_GO_AHEAD);
        codec.local_will[OPT_SUPPRESS_GO_AHEAD as usize] = true;
        codec.queue_command(DO, OPT_SUPPRESS_GO_AHEAD);
        codec.queue_command(DO, OPT_ECHO);
        codec.queue_naws();
        codec
    }

    fn process(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for &byte in input {
            match self.state {
                ParseState::Data => {
                    if byte == IAC {
                        self.state = ParseState::Iac;
                    } else {
                        output.push(byte);
                    }
                }
                ParseState::Iac => {
                    self.state = match byte {
                        IAC => {
                            output.push(IAC);
                            ParseState::Data
                        }
                        WILL => ParseState::Will,
                        WONT => ParseState::Wont,
                        DO => ParseState::Do,
                        DONT => ParseState::Dont,
                        SB => ParseState::SbOption,
                        _ => ParseState::Data,
                    };
                }
                ParseState::Will => {
                    self.handle_will(byte);
                    self.state = ParseState::Data;
                }
                ParseState::Wont => {
                    self.peer_will[byte as usize] = false;
                    self.queue_command(DONT, byte);
                    self.state = ParseState::Data;
                }
                ParseState::Do => {
                    self.handle_do(byte);
                    self.state = ParseState::Data;
                }
                ParseState::Dont => {
                    self.local_will[byte as usize] = false;
                    self.queue_command(WONT, byte);
                    self.state = ParseState::Data;
                }
                ParseState::SbOption => {
                    self.sb_option = byte;
                    self.sb_data.clear();
                    self.state = ParseState::SbData;
                }
                ParseState::SbData => {
                    if byte == IAC {
                        self.state = ParseState::SbIac;
                    } else {
                        self.sb_data.push(byte);
                    }
                }
                ParseState::SbIac => {
                    if byte == SE {
                        self.finish_subnegotiation();
                        self.state = ParseState::Data;
                    } else if byte == IAC {
                        self.sb_data.push(IAC);
                        self.state = ParseState::SbData;
                    } else {
                        self.state = ParseState::Data;
                    }
                }
            }
        }
    }

    fn handle_will(&mut self, option: u8) {
        if matches!(option, OPT_ECHO | OPT_SUPPRESS_GO_AHEAD) {
            if !self.peer_will[option as usize] {
                self.queue_command(DO, option);
                self.peer_will[option as usize] = true;
            }
        } else {
            self.queue_command(DONT, option);
        }
    }

    fn handle_do(&mut self, option: u8) {
        if matches!(option, OPT_TERMINAL_TYPE | OPT_NAWS | OPT_SUPPRESS_GO_AHEAD) {
            if !self.local_will[option as usize] {
                self.queue_command(WILL, option);
                self.local_will[option as usize] = true;
            }
            if option == OPT_NAWS {
                self.queue_naws();
            }
        } else {
            self.queue_command(WONT, option);
        }
    }

    fn finish_subnegotiation(&mut self) {
        if self.sb_option == OPT_TERMINAL_TYPE && self.sb_data.first() == Some(&TTYPE_SEND) {
            self.control.extend([IAC, SB, OPT_TERMINAL_TYPE, TTYPE_IS]);
            self.control.extend(b"xterm-256color");
            self.control.extend([IAC, SE]);
        }
    }

    fn queue_command(&mut self, command: u8, option: u8) {
        self.control.extend([IAC, command, option]);
    }

    fn queue_naws(&mut self) {
        self.control.extend([IAC, SB, OPT_NAWS]);
        for byte in self
            .cols
            .to_be_bytes()
            .into_iter()
            .chain(self.rows.to_be_bytes())
        {
            self.control.push_back(byte);
            if byte == IAC {
                self.control.push_back(IAC);
            }
        }
        self.control.extend([IAC, SE]);
    }

    fn set_size(&mut self, cols: u16, rows: u16) {
        self.cols = cols;
        self.rows = rows;
        if self.local_will[OPT_NAWS as usize] {
            self.queue_naws();
        }
    }

    fn take_control(&mut self) -> Vec<u8> {
        self.control.drain(..).collect()
    }
}

pub struct TelnetTransport {
    stream: TcpStream,
    codec: TelnetCodec,
    cooked: VecDeque<u8>,
}

impl TelnetTransport {
    fn try_flush_control(&mut self) -> Result<(), String> {
        if self.codec.control.is_empty() {
            return Ok(());
        }
        let pending: Vec<u8> = self.codec.control.iter().copied().collect();
        match self.stream.try_write(&pending) {
            Ok(written) => {
                self.codec.control.drain(..written);
                Ok(())
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(format!("Telnet negotiation failed: {error}")),
        }
    }
}

impl Transport for TelnetTransport {
    fn read<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, String>> + Send + 'a {
        async move {
            if !self.cooked.is_empty() {
                return Ok(drain_bytes(&mut self.cooked, buffer));
            }
            self.try_flush_control()?;

            loop {
                let mut raw = [0_u8; 4096];
                let length = self
                    .stream
                    .read(&mut raw)
                    .await
                    .map_err(|error| format!("Telnet read failed: {error}"))?;
                if length == 0 {
                    return Ok(0);
                }
                let mut cooked = Vec::with_capacity(length);
                self.codec.process(&raw[..length], &mut cooked);
                self.cooked.extend(cooked);
                self.try_flush_control()?;
                if !self.cooked.is_empty() {
                    return Ok(drain_bytes(&mut self.cooked, buffer));
                }
            }
        }
    }

    fn write_all<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> impl std::future::Future<Output = Result<(), String>> + Send + 'a {
        async move {
            let control = self.codec.take_control();
            if !control.is_empty() {
                self.stream
                    .write_all(&control)
                    .await
                    .map_err(|error| format!("Telnet negotiation failed: {error}"))?;
            }
            let mut escaped = Vec::with_capacity(bytes.len());
            for &byte in bytes {
                escaped.push(byte);
                if byte == IAC {
                    escaped.push(IAC);
                }
            }
            self.stream
                .write_all(&escaped)
                .await
                .map_err(|error| format!("Telnet write failed: {error}"))
        }
    }

    fn resize(
        &mut self,
        cols: u16,
        rows: u16,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async move {
            self.codec.set_size(cols, rows);
            let control = self.codec.take_control();
            if !control.is_empty() {
                self.stream
                    .write_all(&control)
                    .await
                    .map_err(|error| format!("Telnet NAWS resize failed: {error}"))?;
            }
            Ok(())
        }
    }

    fn shutdown(&mut self) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async move {
            self.stream
                .shutdown()
                .await
                .map_err(|error| format!("Telnet disconnect failed: {error}"))
        }
    }
}

fn drain_bytes(pending: &mut VecDeque<u8>, buffer: &mut [u8]) -> usize {
    let length = pending.len().min(buffer.len());
    for slot in &mut buffer[..length] {
        *slot = pending.pop_front().unwrap();
    }
    length
}

pub async fn connect(
    host: &str,
    port: u16,
    cols: u16,
    rows: u16,
    on_event: &Channel<ConsoleEvent>,
) -> Result<TelnetTransport, String> {
    let host = host.trim();
    crate::commands::validation::validate_host(host)?;
    let connect_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let _ = on_event.send(ConsoleEvent::Status {
        state: "connecting".into(),
        message: format!("Connecting to {connect_host}:{port} over Telnet…"),
    });
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((connect_host, port)))
        .await
        .map_err(|_| format!("Telnet connection to {connect_host}:{port} timed out."))?
        .map_err(|error| match error.kind() {
            ErrorKind::ConnectionRefused => {
                format!("Telnet connection to {connect_host}:{port} was refused.")
            }
            ErrorKind::TimedOut => format!("Telnet connection to {connect_host}:{port} timed out."),
            _ => format!("Telnet connection failed: {error}"),
        })?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("Could not configure the Telnet socket: {error}"))?;
    let mut transport = TelnetTransport {
        stream,
        codec: TelnetCodec::new(cols, rows),
        cooked: VecDeque::new(),
    };
    let initial = transport.codec.take_control();
    transport
        .stream
        .write_all(&initial)
        .await
        .map_err(|error| format!("Telnet negotiation failed: {error}"))?;
    let _ = on_event.send(ConsoleEvent::Status {
        state: "connected".into(),
        message: format!("Telnet connected to {connect_host}:{port}. Traffic is unencrypted."),
    });
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_negotiation_and_preserves_literal_iac() {
        let mut codec = TelnetCodec::new(80, 24);
        codec.take_control();
        let mut output = Vec::new();
        codec.process(
            &[b'a', IAC, WILL, OPT_ECHO, b'b', IAC, IAC, b'c'],
            &mut output,
        );
        assert_eq!(output, [b'a', b'b', IAC, b'c']);
        assert_eq!(codec.take_control(), [IAC, DO, OPT_ECHO]);
    }

    #[test]
    fn answers_terminal_type_and_encodes_naws() {
        let mut codec = TelnetCodec::new(255, 24);
        codec.take_control();
        let mut output = Vec::new();
        codec.process(
            &[IAC, SB, OPT_TERMINAL_TYPE, TTYPE_SEND, IAC, SE],
            &mut output,
        );
        assert!(output.is_empty());
        assert_eq!(
            codec.take_control(),
            [
                IAC,
                SB,
                OPT_TERMINAL_TYPE,
                TTYPE_IS,
                b'x',
                b't',
                b'e',
                b'r',
                b'm',
                b'-',
                b'2',
                b'5',
                b'6',
                b'c',
                b'o',
                b'l',
                b'o',
                b'r',
                IAC,
                SE,
            ]
        );

        codec.set_size(255, 24);
        assert_eq!(
            codec.take_control(),
            [IAC, SB, OPT_NAWS, 0, IAC, IAC, 0, 24, IAC, SE]
        );
    }

    #[test]
    fn rejects_unknown_options() {
        let mut codec = TelnetCodec::new(80, 24);
        codec.take_control();
        let mut output = Vec::new();
        codec.process(&[IAC, WILL, 99, IAC, DO, 100], &mut output);
        assert_eq!(codec.take_control(), [IAC, DONT, 99, IAC, WONT, 100]);
    }
}
