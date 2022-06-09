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
