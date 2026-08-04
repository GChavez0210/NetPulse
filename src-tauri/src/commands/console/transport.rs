/// Common contract for interactive console transports.
///
/// The session task owns one transport and selects between reads and commands.
/// Native async methods let SSH retain its `Channel` handle for PTY resizes,
/// while Telnet and serial adapt their byte streams behind the same interface.
pub trait Transport: Send + Unpin + 'static {
    fn read<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, String>> + Send + 'a;
    fn write_all<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> impl std::future::Future<Output = Result<(), String>> + Send + 'a;

    fn resize(
        &mut self,
        cols: u16,
        rows: u16,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async move {
            let _ = (cols, rows);
            Ok(())
        }
    }

    fn shutdown(&mut self) -> impl std::future::Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }
}
