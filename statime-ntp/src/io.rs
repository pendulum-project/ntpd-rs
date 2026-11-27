/// Write trait for structs that implement std::io::Write without doing blocking io
pub trait NonBlockingWrite: std::io::Write {}

impl<W> NonBlockingWrite for std::io::Cursor<W> where std::io::Cursor<W>: std::io::Write {}
impl NonBlockingWrite for Vec<u8> {}
impl NonBlockingWrite for &mut [u8] {}
impl NonBlockingWrite for std::collections::VecDeque<u8> {}
impl<W> NonBlockingWrite for Box<W> where W: NonBlockingWrite {}
impl<W> NonBlockingWrite for &mut W where W: NonBlockingWrite {}
