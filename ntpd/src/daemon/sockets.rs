use std::fs::Permissions;
use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_json<T>(stream: &mut (impl AsyncWrite + Unpin), value: &T) -> std::io::Result<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value).unwrap();
    stream.write_u64(bytes.len() as u64).await?;
    stream.write_all(&bytes).await
}

pub async fn read_json<'a, T>(
    stream: &mut (impl AsyncRead + Unpin),
    buffer: &'a mut Vec<u8>,
) -> std::io::Result<T>
where
    T: serde::Deserialize<'a>,
{
    buffer.clear();

    #[allow(clippy::cast_possible_truncation)]
    let msg_size = stream.read_u64().await? as usize;
    buffer.resize(msg_size, 0);

    stream.read_exact(buffer).await?;

    serde_json::from_slice(buffer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

fn other_error<T>(msg: String) -> std::io::Result<T> {
    use std::io::{Error, ErrorKind};
    Err(Error::new(ErrorKind::Other, msg))
}

pub fn create_unix_socket_with_permissions(
    path: &Path,
    permissions: Permissions,
) -> std::io::Result<tokio::net::UnixListener> {
    let listener = create_unix_socket(path)?;

    std::fs::set_permissions(path, permissions)?;

    Ok(listener)
}

fn create_unix_socket(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    // must unlink path before the bind below (otherwise we get "address already in use")
    if path.exists() {
        use std::os::unix::fs::FileTypeExt;

        let meta = std::fs::metadata(path)?;
        if !meta.file_type().is_socket() {
            return other_error(format!("path {path:?} exists but is not a socket"));
        }

        std::fs::remove_file(path)?;
    }

    // OS errors are terrible; let's try to do better
    let error = match tokio::net::UnixListener::bind(path) {
        Ok(listener) => return Ok(listener),
        Err(e) => e,
    };

    // we don create parent directories
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            let msg = format!(
                r"Could not create observe socket at {:?} because its parent directory does not exist",
                &path
            );
            return other_error(msg);
        }
    }

    // otherwise, just forward the OS error
    let msg = format!(
        "Could not create observe socket at {:?}: {:?}",
        &path, error
    );

    other_error(msg)
}

#[cfg(test)]
mod tests {
    use tokio::net::{UnixListener, UnixStream};

    use super::*;

    #[tokio::test]
    async fn write_then_read_is_identity() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-1");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        let listener = UnixListener::bind(&path).unwrap();
        let mut writer = UnixStream::connect(&path).await.unwrap();

        let (mut reader, _) = listener.accept().await.unwrap();

        let object = vec![10u64; 1_000];

        write_json(&mut writer, &object).await.unwrap();

        let mut buf = Vec::new();
        let output = read_json::<Vec<u64>>(&mut reader, &mut buf).await.unwrap();

        assert_eq!(object, output);

        // the logic will automatically grow the buffer to the required size
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn invalid_input_is_io_error() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        let path = std::env::temp_dir().join("ntp-test-stream-5");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        let listener = UnixListener::bind(&path).unwrap();
        let mut writer = UnixStream::connect(&path).await.unwrap();

        let (mut reader, _) = listener.accept().await.unwrap();

        // write data that cannot be parsed
        let data = [0; 24];
        writer.write_u64(data.len() as u64).await.unwrap();
        writer.write_all(&data).await.unwrap();

        let mut buf = Vec::new();
        let output = read_json::<Vec<usize>>(&mut reader, &mut buf)
            .await
            .unwrap_err();

        assert_eq!(output.kind(), std::io::ErrorKind::InvalidInput);

        // the logic will automatically grow the buffer to the required size
        assert!(!buf.is_empty());
    }
}
