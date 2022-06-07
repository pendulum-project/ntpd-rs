use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

pub async fn write_json<T>(stream: &mut UnixStream, value: &T) -> std::io::Result<()>
where
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value).unwrap();
    write(stream, &bytes).await
}

pub async fn write(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    loop {
        // Wait for the socket to be writable
        stream.writable().await?;

        // Try to write data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_write(bytes) {
            Ok(_) => {
                // shutdown indicates we won't be writing to this stream any more
                return stream.shutdown().await;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
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
    loop {
        // Wait for the socket to be readable
        stream.readable().await?;

        // Try to read data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_read_buf(buffer) {
            Ok(n) => {
                buffer.truncate(n);
                return Ok(());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}
