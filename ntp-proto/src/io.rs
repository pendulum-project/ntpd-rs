/// Write trait for structs that implement `std::io::Write` without doing blocking io
pub trait NonBlockingWrite: std::io::Write {}

impl<W> NonBlockingWrite for std::io::Cursor<W> where std::io::Cursor<W>: std::io::Write {}
impl NonBlockingWrite for Vec<u8> {}
impl NonBlockingWrite for &mut [u8] {}
impl NonBlockingWrite for std::collections::VecDeque<u8> {}
impl<W> NonBlockingWrite for Box<W> where W: NonBlockingWrite {}
impl<W> NonBlockingWrite for &mut W where W: NonBlockingWrite {}

pub trait NonBlockingRead: std::io::Read {}

impl<R> NonBlockingRead for std::io::Cursor<R> where std::io::Cursor<R>: std::io::Read {}
impl NonBlockingRead for &[u8] {}
impl NonBlockingRead for std::collections::VecDeque<u8> {}
impl<R> NonBlockingRead for Box<R> where R: NonBlockingRead {}
impl<R> NonBlockingRead for &mut R where R: NonBlockingRead {}
