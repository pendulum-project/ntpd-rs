use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::net::UnixStream;

pub async fn write_json<T>(stream: &mut UnixStream, value: &T) -> std::io::Result<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value).unwrap();
    stream.write_all(&bytes).await
}

pub async fn read_json<'a, T>(
    stream: &mut UnixStream,
    buffer: &'a mut Vec<u8>,
) -> std::io::Result<T>
where
    T: serde::Deserialize<'a>,
{
    buffer.clear();

    let n = stream.read_buf(buffer).await?;
    buffer.truncate(n);

    Ok(serde_json::from_slice(buffer).unwrap())
}

pub fn create_unix_socket(path: &Path) -> std::io::Result<UnixListener> {
    use std::io::{Error, ErrorKind};

    // must unlink path before the bind below (otherwise we get "address already in use")
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    // OS errors are terrible; let's try to do better
    let error = match UnixListener::bind(&path) {
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
            return Err(Error::new(ErrorKind::Other, msg));
        }
    }

    // otherwise, just forward the OS error
    let msg = format!(
        "Could not create observe socket at {:?}: {:?}",
        &path, error
    );
    Err(Error::new(ErrorKind::Other, msg))
}

#[cfg(test)]
mod tests {
    use tokio::net::UnixListener;

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

        let object = vec![0usize, 10];

        write_json(&mut writer, &object).await.unwrap();

        let mut buf = Vec::new();
        let output = read_json::<Vec<usize>>(&mut reader, &mut buf)
            .await
            .unwrap();

        assert_eq!(object, output);

        // the logic will automatically grow the buffer to the required size
        assert!(!buf.is_empty());
    }
}
