use std::{
    future::Future,
    io::{IoSlice, Read, Write},
    ops::ControlFlow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ntp_proto::{
    ClientToPool, ClientToPoolConnection, KeyExchangeError, NtsRecord, PoolToServer,
    PoolToServerConnection,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct BoundPoolToServerData<IO> {
    io: IO,
    client: PoolToServer,
    need_flush: bool,
}

// IO approach taken from tokio
impl<IO> BoundPoolToServerData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn do_write(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut writer = WriterAdapter {
            io: &mut self.io,
            cx,
        };

        match self.client.write_socket(&mut writer) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn do_read(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut reader = ReaderAdapter {
            io: &mut self.io,
            cx,
        };
        match self.client.read_socket(&mut reader) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl<IO> Future for BoundPoolToServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<PoolToServerConnection, KeyExchangeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let outer = self.get_mut();
        let mut this = outer.inner.take().unwrap();

        let mut write_blocks = false;
        let mut read_blocks = false;

        loop {
            while !write_blocks && this.client.wants_write() {
                match this.do_write(cx) {
                    Poll::Ready(Ok(_)) => {
                        this.need_flush = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        write_blocks = true;
                        break;
                    }
                }
            }

            if !write_blocks && this.need_flush {
                match Pin::new(&mut this.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        this.need_flush = false;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        write_blocks = true;
                    }
                }
            }

            while !read_blocks && this.client.wants_read() {
                match this.do_read(cx) {
                    Poll::Ready(Ok(_)) => {
                        this.client = match this.client.progress() {
                            ControlFlow::Continue(client) => client,
                            ControlFlow::Break(result) => return Poll::Ready(result),
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            let no_write = write_blocks || !this.client.wants_write();
            let no_read = read_blocks || !this.client.wants_read();
            if no_write && no_read {
                outer.inner = Some(this);
                return Poll::Pending;
            }
        }
    }
}

pub(crate) struct BoundPoolToServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    inner: Option<BoundPoolToServerData<IO>>,
}

impl<IO> BoundPoolToServer<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        io: IO,
        server_name: &str,
        config: rustls::ClientConfig,
        nts_records: &[NtsRecord],
    ) -> Result<Self, KeyExchangeError> {
        Ok(Self {
            inner: Some(BoundPoolToServerData {
                io,
                client: PoolToServer::new(server_name, config, nts_records)?,
                need_flush: false,
            }),
        })
    }
}

pub(crate) struct BoundClientToPool<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    inner: Option<BoundClientToPoolData<IO>>,
}

impl<IO> BoundClientToPool<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: IO, config: Arc<rustls::ServerConfig>) -> Result<Self, KeyExchangeError> {
        let data = BoundClientToPoolData {
            io,
            server: ClientToPool::new(config)?,
            need_flush: false,
        };

        Ok(Self { inner: Some(data) })
    }

    pub async fn run(
        io: IO,
        config: Arc<rustls::ServerConfig>,
    ) -> Result<ClientToPoolConnection, KeyExchangeError> {
        let this = Self::new(io, config)?;

        this.await
    }
}

struct BoundClientToPoolData<IO> {
    io: IO,
    server: ClientToPool,
    need_flush: bool,
}

// IO approach taken from tokio
impl<IO> BoundClientToPoolData<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn do_write(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut writer = WriterAdapter {
            io: &mut self.io,
            cx,
        };

        dbg!("write socket");
        println!(
            "Custom backtrace: {}",
            std::backtrace::Backtrace::force_capture()
        );
        match self.server.write_socket(&mut writer) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    fn do_read(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let mut reader = ReaderAdapter {
            io: &mut self.io,
            cx,
        };
        dbg!("read socket");
        match self.server.read_socket(&mut reader) {
            Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}

impl<IO> Future for BoundClientToPool<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<ClientToPoolConnection, KeyExchangeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let outer = self.get_mut();
        let mut this = outer.inner.take().unwrap();

        let mut write_blocks = false;
        let mut read_blocks = false;

        loop {
            println!("running");
            while !write_blocks && this.server.wants_write() {
                match this.do_write(cx) {
                    Poll::Ready(Ok(_)) => {
                        this.need_flush = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        write_blocks = true;
                        break;
                    }
                }
            }

            if !write_blocks && this.need_flush {
                match Pin::new(&mut this.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        this.need_flush = false;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        write_blocks = true;
                    }
                }
            }

            while dbg!(!read_blocks && this.server.wants_read()) {
                match dbg!(this.do_read(cx)) {
                    Poll::Ready(Ok(_)) => {
                        this.server = match dbg!(this.server.progress()) {
                            ControlFlow::Continue(client) => client,
                            ControlFlow::Break(Ok(x)) => return Poll::Ready(Ok(x)),
                            ControlFlow::Break(Err(e)) => return Poll::Ready(Err(e)),
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        read_blocks = true;
                        break;
                    }
                }
            }

            let no_write = write_blocks || !this.server.wants_write();
            let no_read = read_blocks || !this.server.wants_read();
            if no_write && no_read {
                outer.inner = Some(this);
                println!("done");
                return Poll::Pending;
            }
        }
    }
}

/// adapter between `AsyncWrite` and `std::io::Write`
struct WriterAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncWrite + Unpin> Write for WriterAdapter<'a, 'b, T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match Pin::<&mut T>::new(self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        match Pin::<&mut T>::new(self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match Pin::<&mut T>::new(self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// adapter between `AsyncRead` and `std::io::Read`
struct ReaderAdapter<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncRead + Unpin> Read for ReaderAdapter<'a, 'b, T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut buf = ReadBuf::new(buf);
        match Pin::<&mut T>::new(self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(std::io::ErrorKind::WouldBlock.into()),
        }
    }
}
