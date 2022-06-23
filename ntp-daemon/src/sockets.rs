use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

#[cfg(test)]
mod tests {

    use tokio::net::UnixListener;

    use super::*;

    #[tokio::test]
    async fn test_time_now_does_not_crash() {
        // be careful with copying: tests run concurrently and should use a unique socket name!
        std::fs::remove_file("/tmp/ntp-test-stream-1").unwrap();
        let listener = UnixListener::bind("/tmp/ntp-test-stream-1").unwrap();
        let mut writer = UnixStream::connect("/tmp/ntp-test-stream-1").await.unwrap();

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
