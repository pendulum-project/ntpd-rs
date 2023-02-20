use std::{
    fs::File,
    future::Future,
    io::Write,
    io::{self, BufReader, IoSlice, Read},
    ops::{Deref, DerefMut},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use std::task::ready;

use rustls::{Certificate, ConnectionCommon, PrivateKey, ServerConfig, ServerConnection, SideData};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
};

const NTS_TIME_NL_RESPONSE: &[u8] = &[
    128, 1, 0, 2, 0, 0, 0, 4, 0, 2, 0, 15, 0, 5, 0, 104, 178, 15, 188, 164, 68, 107, 175, 34, 77,
    63, 18, 34, 122, 22, 95, 242, 175, 224, 29, 173, 58, 187, 47, 11, 245, 247, 119, 89, 5, 8, 221,
    162, 106, 66, 30, 65, 218, 13, 108, 238, 12, 29, 200, 9, 92, 218, 38, 20, 238, 251, 68, 35, 44,
    129, 189, 132, 4, 93, 117, 136, 91, 234, 58, 195, 223, 171, 207, 247, 172, 128, 5, 219, 97, 21,
    128, 107, 96, 220, 189, 53, 223, 111, 181, 164, 185, 173, 80, 101, 75, 18, 180, 129, 243, 140,
    253, 236, 45, 62, 101, 155, 252, 51, 102, 97, 0, 5, 0, 104, 178, 15, 188, 164, 106, 99, 31,
    229, 75, 104, 141, 204, 89, 184, 80, 227, 43, 85, 25, 33, 78, 82, 22, 97, 167, 52, 65, 243,
    216, 198, 99, 98, 161, 219, 215, 253, 165, 121, 130, 232, 131, 150, 158, 136, 113, 141, 34,
    223, 42, 122, 185, 132, 185, 153, 158, 249, 192, 80, 167, 251, 116, 45, 179, 151, 82, 248, 13,
    208, 33, 74, 125, 233, 176, 153, 61, 58, 25, 23, 54, 106, 208, 31, 40, 155, 227, 63, 58, 219,
    119, 76, 101, 62, 154, 34, 187, 212, 106, 162, 140, 223, 37, 194, 20, 107, 0, 5, 0, 104, 178,
    15, 188, 164, 240, 20, 28, 103, 149, 25, 37, 145, 187, 196, 100, 113, 36, 76, 171, 29, 69, 40,
    19, 70, 95, 60, 30, 27, 188, 25, 1, 148, 55, 18, 253, 131, 8, 108, 44, 173, 236, 74, 227, 49,
    47, 183, 156, 118, 152, 88, 31, 254, 134, 220, 129, 254, 186, 117, 80, 163, 167, 223, 208, 8,
    124, 141, 240, 43, 161, 240, 60, 54, 241, 44, 87, 135, 116, 63, 236, 40, 138, 162, 65, 143,
    193, 98, 44, 9, 61, 189, 89, 19, 45, 94, 6, 102, 82, 8, 175, 206, 87, 132, 51, 63, 0, 5, 0,
    104, 178, 15, 188, 164, 56, 48, 71, 172, 153, 142, 223, 150, 73, 72, 201, 236, 26, 68, 29, 14,
    139, 66, 190, 77, 218, 206, 90, 117, 75, 128, 88, 186, 187, 156, 130, 57, 198, 118, 176, 199,
    55, 56, 173, 109, 35, 37, 15, 223, 17, 53, 110, 167, 251, 167, 208, 44, 158, 89, 113, 22, 178,
    92, 235, 114, 176, 41, 255, 172, 175, 191, 227, 29, 85, 70, 152, 125, 67, 125, 96, 151, 151,
    160, 188, 8, 35, 205, 152, 142, 225, 59, 71, 224, 254, 84, 20, 51, 162, 164, 94, 241, 7, 15, 9,
    138, 0, 5, 0, 104, 178, 15, 188, 164, 198, 114, 113, 134, 102, 130, 116, 104, 6, 6, 81, 118,
    89, 146, 119, 198, 80, 135, 104, 155, 101, 107, 51, 215, 243, 241, 163, 55, 84, 206, 179, 241,
    105, 210, 184, 30, 44, 133, 235, 227, 87, 7, 40, 230, 185, 47, 180, 189, 84, 157, 182, 81, 69,
    168, 147, 115, 94, 53, 242, 198, 132, 188, 56, 86, 70, 201, 78, 219, 140, 212, 94, 100, 38,
    106, 168, 35, 57, 236, 156, 41, 86, 176, 225, 129, 152, 206, 49, 176, 252, 29, 235, 180, 161,
    148, 195, 223, 27, 217, 85, 220, 0, 5, 0, 104, 178, 15, 188, 164, 52, 150, 226, 182, 229, 113,
    23, 67, 155, 54, 34, 141, 125, 225, 98, 4, 22, 105, 111, 150, 212, 32, 9, 204, 212, 242, 161,
    213, 135, 199, 246, 74, 160, 126, 167, 94, 174, 76, 11, 228, 13, 251, 20, 135, 0, 197, 207, 18,
    168, 118, 218, 39, 79, 100, 203, 234, 224, 116, 59, 234, 247, 156, 128, 58, 104, 57, 204, 85,
    48, 68, 229, 37, 20, 146, 159, 67, 49, 235, 142, 58, 225, 149, 187, 3, 11, 146, 193, 114, 122,
    160, 19, 180, 146, 196, 50, 229, 22, 10, 86, 219, 0, 5, 0, 104, 178, 15, 188, 164, 98, 15, 6,
    117, 71, 114, 79, 45, 197, 158, 30, 187, 51, 12, 43, 131, 252, 74, 92, 251, 139, 159, 99, 163,
    149, 111, 89, 184, 95, 125, 73, 106, 62, 214, 210, 50, 190, 83, 138, 46, 65, 126, 152, 54, 137,
    189, 19, 247, 37, 116, 79, 178, 83, 51, 31, 129, 24, 172, 108, 58, 10, 171, 128, 40, 220, 250,
    168, 133, 164, 32, 47, 19, 231, 181, 124, 242, 192, 212, 153, 25, 10, 165, 52, 170, 177, 42,
    232, 2, 77, 246, 118, 192, 68, 96, 152, 77, 238, 130, 53, 128, 0, 5, 0, 104, 178, 15, 188, 164,
    208, 86, 125, 128, 153, 10, 107, 157, 50, 100, 148, 177, 10, 163, 41, 208, 32, 142, 176, 21,
    10, 15, 39, 208, 111, 47, 233, 154, 23, 161, 191, 192, 105, 242, 25, 68, 234, 211, 81, 89, 244,
    142, 184, 187, 236, 171, 34, 23, 227, 55, 207, 94, 48, 71, 236, 188, 146, 223, 77, 213, 74,
    234, 190, 192, 151, 172, 223, 158, 44, 230, 247, 248, 212, 245, 43, 131, 80, 57, 187, 105, 148,
    232, 15, 107, 239, 84, 131, 9, 222, 225, 137, 73, 202, 40, 48, 57, 122, 198, 245, 40, 128, 0,
    0, 0,
];

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = ("localhost", 4460u16);

    // geneted using openssl
    // ```
    // openssl req -nodes -x509 -days 3650 -subj "/C=NL/L=Nijmegen/O=TG/CN=localhost/" -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
    // openssl req -nodes -new -newkey rsa:4096 -subj "/C=NL/L=Nijmegen/O=TG/CN=localhost/" -addext "subjectAltName = DNS:localhost" -keyout tls.key -out tls.crt
    // openssl x509 -req -extfile <(printf "subjectAltName=DNS:example.com,DNS:www.example.com") -in tls.crt -days 3650 -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out signed.crt
    // openssl x509 -in signed.crt -text -noout
    // ```
    let certs = load_certs(Path::new("test-keys/signed.crt")).unwrap();
    let mut keys = load_keys(Path::new("test-keys/tls.key")).unwrap();

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    println!("listener running on {:?}", &addr);
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = async move {
            use tokio::io::AsyncWriteExt;

            let stream = acceptor.accept(stream).await?;
            let (_reader, mut writer) = tokio::io::split(stream);

            writer.write_all(NTS_TIME_NL_RESPONSE).await?;
            writer.flush().await?;
            println!("Responded to: {}", peer_addr);

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let keys: Vec<PrivateKey> = rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;

    // so instead of `rsa_private_keys`, maybe try `pkcs8_private_keys` or one of the other formats
    assert!(
        !keys.is_empty(),
        r"could not parse any keys. the parser returns an empty vec when the format does not match"
    );

    Ok(keys)
}

/// A wrapper around a `rustls::ServerConfig`, providing an async `accept` method.
#[derive(Clone)]
struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> TlsAcceptor {
        TlsAcceptor { inner }
    }
}

impl TlsAcceptor {
    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = match ServerConnection::new(self.inner.clone()) {
            Ok(session) => session,
            Err(error) => {
                return Accept(MidHandshake::Error {
                    io: stream,
                    // TODO(eliza): should this really return an `io::Error`?
                    // Probably not...
                    error: io::Error::new(io::ErrorKind::Other, error),
                });
            }
        };
        f(&mut session);

        Accept(MidHandshake::Handshaking(TlsStream {
            session,
            io: stream,
            state: TlsState::Stream,
        }))
    }
}

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> Accept<IO> {
    pub fn get_ref(&self) -> Option<&IO> {
        match &self.0 {
            MidHandshake::Handshaking(sess) => Some(sess.get_ref().0),
            MidHandshake::Error { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut IO> {
        match &mut self.0 {
            MidHandshake::Handshaking(sess) => Some(sess.get_mut().0),
            MidHandshake::Error { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }
}

pub(crate) enum MidHandshake<IS: IoSession> {
    Handshaking(IS),
    End,
    Error { io: IS::Io, error: io::Error },
}

impl<IS, SD> Future for MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin,
    SD: SideData,
{
    type Output = Result<IS, (io::Error, IS::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match std::mem::replace(this, MidHandshake::End) {
            MidHandshake::Handshaking(stream) => stream,
            // Starting the handshake returned an error; fail the future immediately.
            MidHandshake::Error { io, error } => return Poll::Ready(Err((error, io))),
            _ => panic!("unexpected polling after handshake"),
        };

        if !stream.skip_handshake() {
            let (state, io, session) = stream.get_mut();
            let mut tls_stream = Stream::new(io, session).set_eof(!state.readable());

            macro_rules! try_poll {
                ( $e:expr ) => {
                    match $e {
                        Poll::Ready(Ok(_)) => (),
                        Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                        Poll::Pending => {
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                };
            }

            while tls_stream.session.is_handshaking() {
                try_poll!(tls_stream.handshake(cx));
            }

            try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
        }

        Poll::Ready(Ok(stream))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ServerConnection,
    pub(crate) state: TlsState,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ServerConnection) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, ServerConnection) {
        (self.io, self.session)
    }
}

pub(crate) trait IoSession {
    type Io;
    type Session;

    fn skip_handshake(&self) -> bool;
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session);
    fn into_io(self) -> Self::Io;
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ServerConnection;

    #[inline]
    fn skip_handshake(&self) -> bool {
        false
    }

    #[inline]
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session) {
        (&mut self.state, &mut self.io, &mut self.session)
    }

    #[inline]
    fn into_io(self) -> Self::Io {
        self.io
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

        match &this.state {
            TlsState::Stream | TlsState::WriteShutdown => {
                let prev = buf.remaining();

                match stream.as_mut_pin().poll_read(cx, buf) {
                    Poll::Ready(Ok(())) => {
                        if prev == buf.remaining() || stream.eof {
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
                        this.state.shutdown_read();
                        Poll::Ready(Err(err))
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(())),
        }
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub enum TlsState {
    Stream,
    ReadShutdown,
    WriteShutdown,
    FullyShutdown,
}

impl TlsState {
    #[inline]
    pub fn shutdown_read(&mut self) {
        match *self {
            TlsState::WriteShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
            _ => *self = TlsState::ReadShutdown,
        }
    }

    #[inline]
    pub fn shutdown_write(&mut self) {
        match *self {
            TlsState::ReadShutdown | TlsState::FullyShutdown => *self = TlsState::FullyShutdown,
            _ => *self = TlsState::WriteShutdown,
        }
    }

    #[inline]
    pub fn writeable(&self) -> bool {
        !matches!(*self, TlsState::WriteShutdown | TlsState::FullyShutdown)
    }

    #[inline]
    pub fn readable(&self) -> bool {
        !matches!(*self, TlsState::ReadShutdown | TlsState::FullyShutdown)
    }

    #[inline]
    #[cfg(feature = "early-data")]
    pub fn is_early_data(&self) -> bool {
        matches!(self, TlsState::EarlyData(..))
    }

    #[inline]
    #[cfg(not(feature = "early-data"))]
    pub const fn is_early_data(&self) -> bool {
        false
    }
}

pub struct Stream<'a, IO, C> {
    pub io: &'a mut IO,
    pub session: &'a mut C,
    pub eof: bool,
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, C, SD> Stream<'a, IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    pub fn new(io: &'a mut IO, session: &'a mut C) -> Self {
        Stream {
            io,
            session,
            // The state so far is only used to detect EOF, so either Stream
            // or EarlyData state should both be all right.
            eof: false,
        }
    }

    pub fn set_eof(mut self, eof: bool) -> Self {
        self.eof = eof;
        self
    }

    pub fn as_mut_pin(&mut self) -> Pin<&mut Self> {
        Pin::new(self)
    }

    pub fn read_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        let mut reader = SyncReadAdapter { io: self.io, cx };

        let n = match self.session.read_tls(&mut reader) {
            Ok(n) => n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(err) => return Poll::Ready(Err(err)),
        };

        let stats = self.session.process_new_packets().map_err(|err| {
            // In case we have an alert to send describing this error,
            // try a last-gasp write -- but don't predate the primary
            // error.
            let _ = self.write_io(cx);

            io::Error::new(io::ErrorKind::InvalidData, err)
        })?;

        if stats.peer_has_closed() && self.session.is_handshaking() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls handshake alert",
            )));
        }

        Poll::Ready(Ok(n))
    }

    pub fn write_io(&mut self, cx: &mut Context) -> Poll<io::Result<usize>> {
        struct Writer<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>,
        }

        impl<'a, 'b, T: Unpin> Writer<'a, 'b, T> {
            #[inline]
            fn poll_with<U>(
                &mut self,
                f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<U>>,
            ) -> io::Result<U> {
                match f(Pin::new(self.io), self.cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        impl<'a, 'b, T: AsyncWrite + Unpin> Write for Writer<'a, 'b, T> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.poll_with(|io, cx| io.poll_write(cx, buf))
            }

            #[inline]
            fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
                self.poll_with(|io, cx| io.poll_write_vectored(cx, bufs))
            }

            fn flush(&mut self) -> io::Result<()> {
                self.poll_with(|io, cx| io.poll_flush(cx))
            }
        }

        let mut writer = Writer { io: self.io, cx };

        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    pub fn handshake(&mut self, cx: &mut Context) -> Poll<io::Result<(usize, usize)>> {
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            let mut write_would_block = false;
            let mut read_would_block = false;
            let mut need_flush = false;

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(n)) => {
                        wrlen += n;
                        need_flush = true;
                    }
                    Poll::Pending => {
                        write_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            if need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => write_would_block = true,
                }
            }

            while !self.eof && self.session.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => self.eof = true,
                    Poll::Ready(Ok(n)) => rdlen += n,
                    Poll::Pending => {
                        read_would_block = true;
                        break;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (self.eof, self.session.is_handshaking()) {
                (true, true) => {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
                    Poll::Ready(Err(err))
                }
                (_, false) => Poll::Ready(Ok((rdlen, wrlen))),
                (_, true) if write_would_block || read_would_block => {
                    if rdlen != 0 || wrlen != 0 {
                        Poll::Ready(Ok((rdlen, wrlen)))
                    } else {
                        Poll::Pending
                    }
                }
                (..) => continue,
            };
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, C, SD> AsyncRead for Stream<'a, IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut io_pending = false;

        // read a packet
        while !self.eof && self.session.wants_read() {
            match self.read_io(cx) {
                Poll::Ready(Ok(0)) => {
                    break;
                }
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        match self.session.reader().read(buf.initialize_unfilled()) {
            // If Rustls returns `Ok(0)` (while `buf` is non-empty), the peer closed the
            // connection with a `CloseNotify` message and no more data will be forthcoming.
            //
            // Rustls yielded more data: advance the buffer, then see if more data is coming.
            //
            // We don't need to modify `self.eof` here, because it is only a temporary mark.
            // rustls will only return 0 if is has received `CloseNotify`,
            // in which case no additional processing is required.
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }

            // Rustls doesn't have more data to yield, but it believes the connection is open.
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    // If `wants_read()` is satisfied, rustls will not return `WouldBlock`.
                    // but if it does, we can try again.
                    //
                    // If the rustls state is abnormal, it may cause a cyclic wakeup.
                    // but tokio's cooperative budget will prevent infinite wakeup.
                    cx.waker().wake_by_ref();
                }

                Poll::Pending
            }

            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<'a, IO: AsyncRead + AsyncWrite + Unpin, C, SD> AsyncWrite for Stream<'a, IO, C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut pos = 0;

        while pos != buf.len() {
            let mut would_block = false;

            match self.session.writer().write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(err) => return Poll::Ready(Err(err)),
            };

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)),
                (_, false) => continue,
            };
        }

        Poll::Ready(Ok(pos))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.session.writer().flush()?;
        while self.session.wants_write() {
            ready!(self.write_io(cx))?;
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            ready!(self.write_io(cx))?;
        }
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// An adapter that implements a [`Read`] interface for [`AsyncRead`] types and an
/// associated [`Context`].
///
/// Turns `Poll::Pending` into `WouldBlock`.
pub struct SyncReadAdapter<'a, 'b, T> {
    pub io: &'a mut T,
    pub cx: &'a mut Context<'b>,
}

impl<'a, 'b, T: AsyncRead + Unpin> Read for SyncReadAdapter<'a, 'b, T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
