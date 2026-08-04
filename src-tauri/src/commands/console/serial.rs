use std::io::ErrorKind as IoErrorKind;

use serde::Serialize;
use tauri::ipc::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_serial::{
    DataBits, FlowControl, Parity, SerialPortBuilderExt, SerialPortType, SerialStream, StopBits,
};

use super::transport::Transport;
use super::ConsoleEvent;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialPortEntry {
    pub path: String,
    pub label: String,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
}

pub struct SerialTransport {
    stream: SerialStream,
    port: String,
}

impl Transport for SerialTransport {
    fn read<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, String>> + Send + 'a {
        async move {
            self.stream
                .read(buffer)
                .await
                .map_err(|error| map_io_error(&self.port, "read", error))
        }
    }

    fn write_all<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> impl std::future::Future<Output = Result<(), String>> + Send + 'a {
        async move {
            self.stream
                .write_all(bytes)
                .await
                .map_err(|error| map_io_error(&self.port, "write", error))?;
            self.stream
                .flush()
                .await
                .map_err(|error| map_io_error(&self.port, "flush", error))
        }
    }

    fn shutdown(&mut self) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async move {
            self.stream
                .shutdown()
                .await
                .map_err(|error| map_io_error(&self.port, "disconnect", error))
        }
    }
}

fn parse_data_bits(value: u8) -> Result<DataBits, String> {
    match value {
        5 => Ok(DataBits::Five),
        6 => Ok(DataBits::Six),
        7 => Ok(DataBits::Seven),
        8 => Ok(DataBits::Eight),
        _ => Err("Serial data bits must be 5, 6, 7, or 8.".into()),
    }
}

fn parse_parity(value: &str) -> Result<Parity, String> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(Parity::None),
        "odd" => Ok(Parity::Odd),
        "even" => Ok(Parity::Even),
        _ => Err("Serial parity must be none, odd, or even.".into()),
    }
}

fn parse_stop_bits(value: u8) -> Result<StopBits, String> {
    match value {
        1 => Ok(StopBits::One),
        2 => Ok(StopBits::Two),
        _ => Err("Serial stop bits must be 1 or 2.".into()),
    }
}

fn parse_flow_control(value: &str) -> Result<FlowControl, String> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(FlowControl::None),
        "software" => Ok(FlowControl::Software),
        "hardware" => Ok(FlowControl::Hardware),
        _ => Err("Serial flow control must be none, software, or hardware.".into()),
    }
}

fn map_open_error(port: &str, error: tokio_serial::Error) -> String {
    let lower = error.to_string().to_ascii_lowercase();
    match error.kind() {
        tokio_serial::ErrorKind::Io(IoErrorKind::PermissionDenied) if cfg!(target_os = "linux") => {
            "Permission denied — add your user to the 'dialout' group, then log out and back in."
                .into()
        }
        tokio_serial::ErrorKind::Io(IoErrorKind::PermissionDenied)
        | tokio_serial::ErrorKind::NoDevice
            if lower.contains("busy")
                || lower.contains("in use")
                || lower.contains("access is denied") =>
        {
            format!(
                "Serial port {port} is in use by another application (PuTTY, screen, or minicom?)."
            )
        }
        tokio_serial::ErrorKind::NoDevice => {
            format!("Serial port {port} is unavailable or was disconnected.")
        }
        _ => format!("Could not open serial port {port}: {error}"),
    }
}

fn map_io_error(port: &str, operation: &str, error: std::io::Error) -> String {
    match error.kind() {
        IoErrorKind::NotFound
        | IoErrorKind::BrokenPipe
        | IoErrorKind::ConnectionReset
        | IoErrorKind::UnexpectedEof => {
            format!("Serial adapter {port} was disconnected during {operation}.")
        }
        IoErrorKind::PermissionDenied if cfg!(target_os = "linux") => {
            "Permission denied — add your user to the 'dialout' group, then log out and back in."
                .into()
        }
        _ => format!("Serial {operation} failed on {port}: {error}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn connect(
    port: &str,
    baud: u32,
    data_bits: u8,
    parity: &str,
    stop_bits: u8,
    flow_control: &str,
    on_event: &Channel<ConsoleEvent>,
) -> Result<SerialTransport, String> {
    let port = port.trim();
    if port.is_empty() {
        return Err("Select a serial port before connecting.".into());
    }
    if baud == 0 || baud > 4_000_000 {
        return Err("Serial baud rate must be between 1 and 4,000,000.".into());
    }
    let _ = on_event.send(ConsoleEvent::Status {
        state: "connecting".into(),
        message: format!("Opening {port} at {baud} baud…"),
    });
    let stream = tokio_serial::new(port, baud)
        .data_bits(parse_data_bits(data_bits)?)
        .parity(parse_parity(parity)?)
        .stop_bits(parse_stop_bits(stop_bits)?)
        .flow_control(parse_flow_control(flow_control)?)
        .open_native_async()
        .map_err(|error| map_open_error(port, error))?;
    let _ = on_event.send(ConsoleEvent::Status {
        state: "connected".into(),
        message: format!("Serial connected to {port}. Press Enter if the device is silent."),
    });
    Ok(SerialTransport {
        stream,
        port: port.to_string(),
    })
}

pub async fn list_ports() -> Result<Vec<SerialPortEntry>, String> {
    tokio::task::spawn_blocking(|| {
        let mut entries = tokio_serial::available_ports()
            .map_err(|error| format!("Could not enumerate serial ports: {error}"))?
            .into_iter()
            .map(|port| {
                let (manufacturer, product, serial_number, vendor_id, product_id, details) =
                    match port.port_type {
                        SerialPortType::UsbPort(usb) => {
                            let mut names = Vec::new();
                            if let Some(value) = usb.manufacturer.as_deref() {
                                names.push(value.to_string());
                            }
                            if let Some(value) = usb.product.as_deref() {
                                if !names.iter().any(|item| item == value) {
                                    names.push(value.to_string());
                                }
                            }
                            if names.is_empty() {
                                names.push(format!("USB {:04X}:{:04X}", usb.vid, usb.pid));
                            }
                            (
                                usb.manufacturer,
                                usb.product,
                                usb.serial_number,
                                Some(usb.vid),
                                Some(usb.pid),
                                names.join(" "),
                            )
                        }
                        SerialPortType::BluetoothPort => {
                            (None, None, None, None, None, "Bluetooth serial port".into())
                        }
                        SerialPortType::PciPort => {
                            (None, None, None, None, None, "Built-in serial port".into())
                        }
                        SerialPortType::Unknown => {
                            (None, None, None, None, None, "Serial port".into())
                        }
                    };
                SerialPortEntry {
                    label: format!("{} — {}", port.port_name, details),
                    path: port.port_name,
                    manufacturer,
                    product,
                    serial_number,
                    vendor_id,
                    product_id,
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    })
    .await
    .map_err(|error| format!("Serial port discovery task failed: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_serial_parameters() {
        assert!(matches!(parse_data_bits(8), Ok(DataBits::Eight)));
        assert!(parse_data_bits(9).is_err());
        assert!(matches!(parse_parity("even"), Ok(Parity::Even)));
        assert!(parse_parity("mark").is_err());
        assert!(matches!(parse_stop_bits(2), Ok(StopBits::Two)));
        assert!(matches!(
            parse_flow_control("hardware"),
            Ok(FlowControl::Hardware)
        ));
    }
}
