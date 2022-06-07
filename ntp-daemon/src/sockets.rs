use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn write_json<T>(stream: &mut UnixStream, value: &T) -> std::io::Result<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value).unwrap();
    write(stream, &bytes).await
}

pub async fn write(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    stream.writable().await?;

    stream.write_all(bytes).await?;

    stream.shutdown().await
}

pub async fn read_json<'a, T>(
    stream: &mut UnixStream,
    buffer: &'a mut Vec<u8>,
) -> std::io::Result<T>
where
    T: serde::Deserialize<'a>,
{
    buffer.clear();

    read(stream, buffer).await?;

    Ok(serde_json::from_slice(buffer).unwrap())
}

pub async fn read(stream: &mut UnixStream, buffer: &mut Vec<u8>) -> std::io::Result<()> {
    stream.readable().await?;

    buffer.clear();
    let n = stream.read_buf(buffer).await?;
    buffer.truncate(n);

    Ok(())
}
