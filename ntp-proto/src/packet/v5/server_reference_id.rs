use crate::packet::v5::extension_fields::{ReferenceIdRequest, ReferenceIdResponse};
use crate::packet::v5::NtpClientCookie;
use rand::distributions::{Distribution, Standard};
use rand::{thread_rng, Rng};
use std::array::from_fn;
use std::fmt::{Debug, Formatter};

#[derive(Copy, Clone, Debug)]
struct U12(u16);

impl U12 {
    pub const MAX: Self = Self(4095);

    /// For an array of bytes calculate the index at which a bit would live as well as a mask where the
    /// corresponding bit in that byte would be set
    const fn byte_and_mask(self) -> (usize, u8) {
        (self.0 as usize / 8, 1 << (self.0 % 8))
    }
}

impl Distribution<U12> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> U12 {
        U12(rng.gen_range(0..4096))
    }
}

impl From<U12> for u16 {
    fn from(value: U12) -> Self {
        value.0
    }
}

impl TryFrom<u16> for U12 {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value > Self::MAX.into() {
            Err(())
        } else {
            Ok(Self(value))
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ServerId([U12; 10]);

impl ServerId {
    /// Generate a new random `ServerId`
    pub fn new(rng: &mut impl Rng) -> Self {
        // FIXME: sort IDs so we access the filters predictably
        // FIXME: check for double rolls to reduce false positive rate

        Self(from_fn(|_| rng.gen()))
    }
}

impl Default for ServerId {
    fn default() -> Self {
        Self::new(&mut thread_rng())
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct BloomFilter([u8; Self::BYTES]);
impl BloomFilter {
    pub const BYTES: usize = 512;

    #[must_use] pub const fn new() -> Self {
        Self([0; Self::BYTES])
    }

    #[must_use] pub fn contains_id(&self, other: &ServerId) -> bool {
        other.0.iter().all(|idx| self.is_set(*idx))
    }

    pub fn add_id(&mut self, id: &ServerId) {
        for idx in id.0 {
            self.set_bit(idx);
        }
    }

    pub fn add(&mut self, other: &BloomFilter) {
        for (ours, theirs) in self.0.iter_mut().zip(other.0.iter()) {
            *ours |= theirs;
        }
    }

    pub fn union<'a>(others: impl Iterator<Item = &'a BloomFilter>) -> Self {
        let mut union = Self::new();

        for other in others {
            union.add(other);
        }

        union
    }

    #[must_use] pub fn count_ones(&self) -> u16 {
        self.0.iter().map(|b| b.count_ones() as u16).sum()
    }

    #[must_use] pub const fn as_bytes(&self) -> &[u8; Self::BYTES] {
        &self.0
    }

    fn set_bit(&mut self, idx: U12) {
        let (idx, mask) = idx.byte_and_mask();
        self.0[idx] |= mask;
    }

    const fn is_set(&self, idx: U12) -> bool {
        let (idx, mask) = idx.byte_and_mask();
        self.0[idx] & mask != 0
    }
}

impl<'a> FromIterator<&'a BloomFilter> for BloomFilter {
    fn from_iter<T: IntoIterator<Item = &'a BloomFilter>>(iter: T) -> Self {
        Self::union(iter.into_iter())
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for BloomFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str: String = self
            .0
            .chunks_exact(32)
            .map(|chunk| chunk.iter().fold(0, |acc, b| acc | b))
            .map(|b| char::from_u32(0x2800 + u32::from(b)).unwrap())
            .collect();

        f.debug_tuple("BloomFilter").field(&str).finish()
    }
}

pub struct RemoteBloomFilter {
    filter: BloomFilter,
    chunk_size: u16,
    last_requested: Option<(u16, NtpClientCookie)>,
    next_to_request: u16,
    is_filled: bool,
}

impl RemoteBloomFilter {
    /// Create a new `BloomFilter` that can poll chunks from the server
    ///
    /// `chunk_size` has to be:
    /// * divisible by 4
    /// * divide 512 without remainder
    /// * between `4..=512`
    pub const fn new(chunk_size: u16) -> Option<Self> {
        if chunk_size % 4 != 0 {
            return None;
        }

        if chunk_size == 0 || chunk_size > 512 {
            return None;
        }

        if 512 % chunk_size != 0 {
            return None;
        }

        Some(Self {
            filter: BloomFilter::new(),
            chunk_size,
            last_requested: None,
            next_to_request: 0,
            is_filled: false,
        })
    }

    /// Returns the fully fetched filter or None if not all chunks were received yet
    pub fn full_filter(&self) -> Option<&BloomFilter> {
        self.is_filled.then_some(&self.filter)
    }

    pub fn next_request(&mut self, cookie: NtpClientCookie) -> ReferenceIdRequest {
        let offset = self.next_to_request;
        let last_request = self.last_requested.replace((offset, cookie));

        if let Some(_last_request) = last_request {
            // TODO log something about never got a response
        }

        ReferenceIdRequest::new(self.chunk_size, offset)
            .expect("We ensure that our request always falls within the BloomFilter")
    }

    pub fn handle_response(
        &mut self,
        cookie: NtpClientCookie,
        response: &ReferenceIdResponse,
    ) -> Result<(), ResponseHandlingError> {
        let Some((offset, expected_cookie)) = self.last_requested else {
            return Err(ResponseHandlingError::NotAwaitingResponse);
        };

        if cookie != expected_cookie {
            return Err(ResponseHandlingError::MismatchedCookie);
        }

        if response.bytes().len() != self.chunk_size as usize {
            return Err(ResponseHandlingError::MismatchedLength);
        }

        self.filter.0[(offset as usize)..][..(self.chunk_size as usize)]
            .copy_from_slice(response.bytes());
        self.advance_next_to_request();
        self.last_requested = None;

        Ok(())
    }

    fn advance_next_to_request(&mut self) {
        self.next_to_request = (self.next_to_request + self.chunk_size) % BloomFilter::BYTES as u16;

        if self.next_to_request == 0 {
            // We made the round at least once... so we must be fully filled
            self.is_filled = true;
        }
    }
}

impl Debug for RemoteBloomFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteBloomFilter")
            .field("chunk_size", &self.chunk_size)
            .field("last_requested", &self.last_requested)
            .field("next_to_request", &self.next_to_request)
            .field("is_filled", &self.is_filled)
            .finish()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ResponseHandlingError {
    NotAwaitingResponse,
    MismatchedCookie,
    MismatchedLength,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn set_bits() {
        let mut rid = BloomFilter::new();
        assert!(rid.0.iter().all(|x| x == &0));
        assert!((0..4096).all(|idx| !rid.is_set(U12(idx))));
        assert_eq!(rid.count_ones(), 0);

        rid.set_bit(U12(0));
        assert_eq!(rid.count_ones(), 1);
        assert!(rid.is_set(U12(0)));
        assert_eq!(rid.0[0], 1);

        rid.set_bit(U12(4));
        assert_eq!(rid.count_ones(), 2);
        assert!(rid.is_set(U12(4)));
        assert_eq!(rid.0[0], 0b0001_0001);

        rid.set_bit(U12::MAX);
        assert_eq!(rid.count_ones(), 3);
        assert!(rid.is_set(U12::MAX));
        assert_eq!(rid.0[511], 0b1000_0000);
    }

    #[test]
    fn set_contains() {
        let mut rng = thread_rng();
        let mut filter = BloomFilter::new();

        let id = ServerId::new(&mut rng);
        assert!(!filter.contains_id(&id));

        filter.add_id(&id);
        assert!(filter.contains_id(&id));

        for _ in 0..128 {
            let rid = ServerId::new(&mut rng);

            filter.add_id(&rid);
            assert!(filter.contains_id(&rid));
        }
    }

    #[test]
    fn set_collect() {
        let mut rng = thread_rng();
        let mut ids = vec![];
        let mut filters = vec![];

        for _ in 0..10 {
            let id = ServerId::new(&mut rng);
            let mut filter = BloomFilter::new();
            filter.add_id(&id);

            ids.push(id);
            filters.push(filter);
        }

        let set: BloomFilter = filters.iter().collect();

        for rid in &ids {
            assert!(set.contains_id(rid));
        }
    }

    #[test]
    fn requesting() {
        use ResponseHandlingError::{MismatchedCookie, MismatchedLength, NotAwaitingResponse};

        let chunk_size = 16;
        let mut bf = RemoteBloomFilter::new(chunk_size).unwrap();

        assert!(matches!(
            bf.handle_response(
                NtpClientCookie::new_random(),
                &ReferenceIdResponse::new(&[0u8; 16]).unwrap()
            ),
            Err(NotAwaitingResponse)
        ));

        let cookie = NtpClientCookie::new_random();
        let req = bf.next_request(cookie);
        assert_eq!(req.offset(), 0);
        assert_eq!(req.payload_len(), chunk_size);

        assert!(matches!(
            bf.handle_response(cookie, &ReferenceIdResponse::new(&[0; 24]).unwrap()),
            Err(MismatchedLength)
        ));

        let mut wrong_cookie = cookie;
        wrong_cookie.0[0] ^= 0xFF; // Flip all bits in first byte
        assert!(matches!(
            bf.handle_response(wrong_cookie, &ReferenceIdResponse::new(&[0; 16]).unwrap()),
            Err(MismatchedCookie)
        ));

        bf.handle_response(cookie, &ReferenceIdResponse::new(&[1; 16]).unwrap())
            .unwrap();
        assert_eq!(bf.next_to_request, 16);
        assert_eq!(bf.last_requested, None);
        assert!(!bf.is_filled);
        assert!(bf.full_filter().is_none());
        assert_eq!(&bf.filter.0[..16], &[1; 16]);
        assert_eq!(&bf.filter.0[16..], &[0; 512 - 16]);

        for chunk in 1..(512 / chunk_size) {
            let cookie = NtpClientCookie::new_random();
            let req = bf.next_request(cookie);
            assert_eq!(req.offset(), chunk * chunk_size);
            assert!(bf.full_filter().is_none());
            let bytes: Vec<_> = (0..req.payload_len()).map(|_| chunk as u8 + 1).collect();
            let response = ReferenceIdResponse::new(&bytes).unwrap();
            bf.handle_response(cookie, &response).unwrap();
        }

        assert_eq!(bf.next_to_request, 0);
        assert!(bf.full_filter().is_some());
    }

    #[test]
    fn works_with_any_chunk_size() {
        let mut target_filter = BloomFilter::new();
        for _ in 0..16 {
            target_filter.add_id(&ServerId::new(&mut thread_rng()));
        }

        for chunk_size in 0..=512 {
            let Some(mut bf) = RemoteBloomFilter::new(chunk_size) else {
                continue;
            };

            for _chunk in 0..=(512 / chunk_size) {
                let cookie = NtpClientCookie::new_random();
                let request = bf.next_request(cookie);
                let response = request.to_response(&target_filter).unwrap();
                bf.handle_response(cookie, &response).unwrap();
            }

            let result_filter = bf.full_filter().unwrap();
            assert_eq!(&target_filter, result_filter);
        }
    }
}
