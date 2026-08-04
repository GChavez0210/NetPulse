use tauri::{AppHandle, Manager};

/// Ceiling on a single exported file. A ten-thousand-line console transcript or
/// a long ping session stays far under this; the cap only bounds what a caller
/// can ask NetPulse to write.
const MAX_EXPORT_BYTES: usize = 32 * 1024 * 1024;

/// Writes an exported report to the downloads folder and returns the path it
/// landed on, so the UI can name the file it just wrote rather than leaving the
/// user to guess where the WebView put it.
#[tauri::command]
pub async fn export_text_file(
    file_name: String,
    text: String,
    app: AppHandle,
) -> Result<String, String> {
    if text.len() > MAX_EXPORT_BYTES {
        return Err("This export is too large to write.".into());
    }

    // File names are built from hostnames and renameable tab labels, so only
    // the final path component is kept and every character outside a safe set
    // is replaced. Nothing here may steer the write out of the target folder.
    let candidate = std::path::Path::new(&file_name)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or_else(|| "That export file name is not usable.".to_string())?;
    let safe_name: String = candidate
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let (stem, extension) = match safe_name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_string(), format!(".{extension}")),
        _ => (safe_name.clone(), String::new()),
    };

    let directory = app
        .path()
        .download_dir()
        .or_else(|_| app.path().document_dir())
        .map_err(|error| format!("Could not resolve a folder to export into: {error}"))?;
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|error| format!("Could not open {}: {error}", directory.display()))?;

    // Every export name carries a timestamp, so a collision means two exports in
    // the same instant; a suffix is cheaper than overwriting someone's capture.
    for attempt in 0..100u32 {
        let name = if attempt == 0 {
            format!("{stem}{extension}")
        } else {
            format!("{stem}-{attempt}{extension}")
        };
        let path = directory.join(name);
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                use tokio::io::AsyncWriteExt as _;
                file.write_all(text.as_bytes())
                    .await
                    .map_err(|error| format!("Could not write {}: {error}", path.display()))?;
                file.flush()
                    .await
                    .map_err(|error| format!("Could not write {}: {error}", path.display()))?;
                return Ok(path.display().to_string());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Could not write {}: {error}", path.display())),
        }
    }

    Err(format!(
        "Could not find an unused file name in {}.",
        directory.display()
    ))
}

#[cfg(test)]
mod tests {
    /// Mirrors the sanitizer above; the command itself needs an AppHandle, so
    /// the part worth pinning down is the name it is willing to write.
    fn sanitize(file_name: &str) -> Option<String> {
        let candidate = std::path::Path::new(file_name)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::trim)
            .filter(|name| !name.is_empty() && *name != "." && *name != "..")?;
        Some(
            candidate
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                        character
                    } else {
                        '-'
                    }
                })
                .collect(),
        )
    }

    #[test]
    fn keeps_ordinary_export_names_intact() {
        assert_eq!(
            sanitize("netpulse-core-sw1-2026-08-04.txt").as_deref(),
            Some("netpulse-core-sw1-2026-08-04.txt")
        );
    }

    #[test]
    fn strips_directory_components_from_a_traversing_name() {
        assert_eq!(sanitize("../../evil.txt").as_deref(), Some("evil.txt"));
        assert_eq!(sanitize("/etc/passwd").as_deref(), Some("passwd"));
    }

    /// Backslash is only a separator on Windows, so what matters on every
    /// platform is that nothing able to redirect a write survives.
    #[test]
    fn leaves_no_separator_in_a_sanitized_name() {
        for name in [
            "a/b:c*d?.csv",
            "C:\\Windows\\System32\\evil.txt",
            "..\\..\\evil.txt",
        ] {
            let sanitized = sanitize(name).expect("name should survive sanitizing");
            assert!(
                !sanitized.contains(['/', '\\', ':']),
                "{name} sanitized to {sanitized}"
            );
            assert!(!sanitized.is_empty());
        }
    }

    #[test]
    fn rejects_names_that_have_no_usable_component() {
        assert_eq!(sanitize(".."), None);
        assert_eq!(sanitize("   "), None);
        assert_eq!(sanitize(""), None);
    }
}
