use std::time::Duration;

use base64::{prelude::BASE64_STANDARD, Engine};
use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use rand::rngs::OsRng;

/// The header constant that is prefixed for each roughtime packet
const HEADER: u64 = 0x4d49544847554f52;

/// A roughtime packet should be at least this size
const MIN_PACKET_SIZE: usize = 1024;

/// The minimum body size for a roughtime packet. This is the minimum packet size,
/// minus 8 bytes for the roughtime header and 4 bytes for the message size.
const MIN_BODY_SIZE: usize = MIN_PACKET_SIZE - 8 - 4;

/// String to be prefixed before signing the delegation data
const ROUGHTIME_DELEGATION_CONTEXT_STRING: &str = "RoughTime v1 delegation signature--\0";

/// String to be prefixed before signing the response data
const ROUGHTIME_RESPONSE_CONTEXT_STRING: &str = "RoughTime v1 response signature\0";

/// Version of the standard this roughtime implementation supports
const SUPPORTED_VERSION: u32 = 0x80000000 + 1;

macro_rules! generate_tags {
    ($($name:ident = $value:expr,)*) => {
        #[derive(Debug)]
        #[repr(u32)]
        enum TagId {
            $($name = $value,)*
        }

        impl TagId {
            fn from_tag(tag: u32) -> Option<TagId> {
                match tag {
                    $($value => Some(TagId::$name),)*
                    _ => None,
                }
            }
        }

        impl From<TagId> for u32 {
            fn from(tag: TagId) -> u32 {
                match tag {
                    $(TagId::$name => $value,)*
                }
            }
        }
    };
}

generate_tags!(
    SIG = 0x00474953,
    SRV = 0x00565253,
    VER = 0x00524556,
    NONC = 0x434e4f4e,
    DELE = 0x454c4544,
    PATH = 0x48544150,
    RADI = 0x49444152,
    PUBK = 0x4b425550,
    MIDP = 0x5044494d,
    SREP = 0x50455253,
    MINT = 0x544e494d,
    ROOT = 0x544f4f52,
    CERT = 0x54524543,
    MAXT = 0x5458414d,
    INDX = 0x58444e49,
    ZZZZ = 0x5a5a5a5a,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct RoughTimestamp(pub u64);

impl RoughTimestamp {
    fn now() -> RoughTimestamp {
        use std::time::{SystemTime, UNIX_EPOCH};

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;
        RoughTimestamp(time)
    }
}

impl std::ops::Add<Duration> for RoughTimestamp {
    type Output = RoughTimestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        RoughTimestamp(rhs.as_secs() + self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Signature([u8; 64]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerResponse {
    root: [u8; 32],
    midpoint: RoughTimestamp,
    radius: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DelegatedKey {
    public_key: [u8; 32],
    min_time: RoughTimestamp,
    max_time: RoughTimestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Certificate {
    delegated: DelegatedKey,
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tag {
    Version(Vec<u32>),
    Nonce([u8; 32]),
    ServerKey([u8; 32]),
    Signature(Signature),
    Path(Vec<[u8; 32]>),
    ServerResponse(ServerResponse),
    Certificate(Certificate),
    Index(u32),
    DelegatedKey(DelegatedKey),
    PublicKey([u8; 32]),
    Midpoint(RoughTimestamp),
    Radius(u32),
    MinTime(RoughTimestamp),
    MaxTime(RoughTimestamp),
    Root([u8; 32]),
    Zeroes(usize),
}

impl Tag {
    fn value_size(&self) -> usize {
        fn size_of_header(field_count: usize) -> usize {
            if field_count == 0 {
                4
            } else {
                field_count * 8
            }
        }

        match self {
            Tag::Version(versions) => versions.len() * 4,
            Tag::Nonce(_) => 32,
            Tag::ServerKey(_) => 32,
            Tag::Signature(_) => 64,
            Tag::Path(paths) => paths.len() * 32,
            Tag::ServerResponse(_) => size_of_header(3) + 32 + 8 + 4,
            Tag::Certificate(_) => size_of_header(2) + size_of_header(3) + 32 + 8 + 8 + 64,
            Tag::Index(_) => 4,
            Tag::DelegatedKey(_) => size_of_header(3) + 32 + 8 + 8,
            Tag::PublicKey(_) => 32,
            Tag::Midpoint(_) => 8,
            Tag::Radius(_) => 4,
            Tag::MinTime(_) => 8,
            Tag::MaxTime(_) => 8,
            Tag::Root(_) => 32,
            Tag::Zeroes(size) => *size,
        }
    }

    fn id(&self) -> TagId {
        match self {
            Tag::Version(_) => TagId::VER,
            Tag::Nonce(_) => TagId::NONC,
            Tag::ServerKey(_) => TagId::SRV,
            Tag::Signature(_) => TagId::SIG,
            Tag::Path(_) => TagId::PATH,
            Tag::ServerResponse(_) => TagId::SREP,
            Tag::Certificate(_) => TagId::CERT,
            Tag::Index(_) => TagId::INDX,
            Tag::DelegatedKey(_) => TagId::DELE,
            Tag::PublicKey(_) => TagId::PUBK,
            Tag::Midpoint(_) => TagId::MIDP,
            Tag::Radius(_) => TagId::RADI,
            Tag::MinTime(_) => TagId::MINT,
            Tag::MaxTime(_) => TagId::MAXT,
            Tag::Root(_) => TagId::ROOT,
            Tag::Zeroes(_) => TagId::ZZZZ,
        }
    }

    async fn write_value<W>(&self, writer: &mut W) -> Result<(), std::io::Error>
    where
        W: tokio::io::AsyncWrite + std::fmt::Debug + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        match self {
            Tag::Version(vec) => {
                for v in vec {
                    writer.write_u32_le(*v).await?;
                }
            }
            Tag::Nonce(n) => {
                writer.write_all(n).await?;
            }
            Tag::ServerKey(sk) => {
                writer.write_all(sk).await?;
            }
            Tag::Signature(signature) => {
                writer.write_all(&signature.0).await?;
            }
            Tag::Path(vec) => {
                for v in vec {
                    writer.write_all(v).await?;
                }
            }
            Tag::ServerResponse(server_response) => {
                let tags = [
                    Tag::Radius(server_response.radius),
                    Tag::Midpoint(server_response.midpoint),
                    Tag::Root(server_response.root),
                ];
                Box::pin(write_roughtime_message(writer, &tags, None)).await?;
            }
            Tag::Certificate(certificate) => {
                let tags = [
                    Tag::DelegatedKey(certificate.delegated),
                    Tag::Signature(certificate.signature),
                ];
                Box::pin(write_roughtime_message(writer, &tags, None)).await?;
            }
            Tag::Index(idx) => {
                writer.write_u32_le(*idx).await?;
            }
            Tag::DelegatedKey(delegated_key) => {
                let tags = [
                    Tag::MinTime(delegated_key.min_time),
                    Tag::MaxTime(delegated_key.max_time),
                    Tag::PublicKey(delegated_key.public_key),
                ];
                Box::pin(write_roughtime_message(writer, &tags, None)).await?;
            }
            Tag::PublicKey(pk) => {
                writer.write_all(pk).await?;
            }
            Tag::Midpoint(rough_timestamp) => {
                writer.write_u64_le(rough_timestamp.0).await?;
            }
            Tag::Radius(r) => {
                writer.write_u32_le(*r).await?;
            }
            Tag::MinTime(rough_timestamp) => {
                writer.write_u64_le(rough_timestamp.0).await?;
            }
            Tag::MaxTime(rough_timestamp) => {
                writer.write_u64_le(rough_timestamp.0).await?;
            }
            Tag::Root(root) => {
                writer.write_all(root).await?;
            }
            Tag::Zeroes(size) => {
                for _ in 0..*size {
                    writer.write_u8(0).await?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RoughRequest {
    version: Vec<u32>,
    nonce: [u8; 32],
    server_key: Option<[u8; 32]>,
}

impl RoughRequest {
    fn from_tags(tags: &[Tag]) -> Result<RoughRequest, ParseError> {
        let mut version = None;
        let mut nonce = None;
        let mut server_key = None;
        for tag in tags {
            match tag {
                Tag::Version(versions) => version = Some(versions.clone()),
                Tag::Nonce(n) => nonce = Some(*n),
                Tag::ServerKey(sk) => server_key = Some(*sk),
                Tag::Zeroes(_) => {}
                _ => return Err(ParseError::UnexpectedTag(tag.clone())),
            }
        }

        let version = version.ok_or(ParseError::MissingTag(TagId::VER))?;
        let nonce = nonce.ok_or(ParseError::MissingTag(TagId::NONC))?;
        Ok(RoughRequest {
            version,
            nonce,
            server_key,
        })
    }

    fn into_tags(&self) -> Vec<Tag> {
        let mut tags = vec![Tag::Version(self.version.clone()), Tag::Nonce(self.nonce)];

        if let Some(server_key) = self.server_key {
            tags.push(Tag::ServerKey(server_key));
        }

        tags
    }
}

#[derive(Debug, Clone)]
struct RoughResponse {
    signature: Signature,
    version: u32,
    nonce: [u8; 32],
    path: Vec<[u8; 32]>,
    server_response: ServerResponse,
    certificate: Certificate,
    index: u32,
}

impl RoughResponse {
    fn from_tags(tags: &[Tag]) -> Result<RoughResponse, ParseError> {
        let mut signature = None;
        let mut version = None;
        let mut nonce = None;
        let mut path = None;
        let mut server_response = None;
        let mut certificate = None;
        let mut index = None;
        for tag in tags {
            match tag {
                Tag::Signature(sig) => signature = Some(*sig),
                Tag::Version(versions) => version = Some(versions[0]),
                Tag::Nonce(n) => nonce = Some(*n),
                Tag::Path(p) => path = Some(p.clone()),
                Tag::ServerResponse(sr) => server_response = Some(*sr),
                Tag::Certificate(c) => certificate = Some(*c),
                Tag::Index(i) => index = Some(*i),
                Tag::Zeroes(_) => {}
                _ => return Err(ParseError::UnexpectedTag(tag.clone())),
            }
        }

        let signature = signature.ok_or(ParseError::MissingTag(TagId::SIG))?;
        let version = version.ok_or(ParseError::MissingTag(TagId::VER))?;
        let nonce = nonce.ok_or(ParseError::MissingTag(TagId::NONC))?;
        let path = path.ok_or(ParseError::MissingTag(TagId::PATH))?;
        let server_response = server_response.ok_or(ParseError::MissingTag(TagId::SREP))?;
        let certificate = certificate.ok_or(ParseError::MissingTag(TagId::CERT))?;
        let index = index.ok_or(ParseError::MissingTag(TagId::INDX))?;
        Ok(RoughResponse {
            signature,
            version,
            nonce,
            path,
            server_response,
            certificate,
            index,
        })
    }

    fn into_tags(&self) -> Vec<Tag> {
        vec![
            Tag::Signature(self.signature),
            Tag::Version(vec![self.version]),
            Tag::Nonce(self.nonce),
            Tag::Path(self.path.clone()),
            Tag::ServerResponse(self.server_response),
            Tag::Certificate(self.certificate),
            Tag::Index(self.index),
        ]
    }
}

#[derive(Debug)]
enum ParseError {
    UnknownTag(u32),
    UnexpectedTag(Tag),
    MissingTag(TagId),
    ZeroesNotZero,
    InvalidHeader,
    IoError(std::io::Error),
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> ParseError {
        ParseError::IoError(err)
    }
}

fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

fn parse_roughtime_tag(tag: u32, data: &[u8]) -> Result<Tag, ParseError> {
    let tag_id = TagId::from_tag(tag).ok_or(ParseError::UnknownTag(tag))?;

    match tag_id {
        TagId::SIG => {
            let mut sig = [0; 64];
            sig.copy_from_slice(data);
            Ok(Tag::Signature(Signature(sig)))
        }
        TagId::SRV => Ok(Tag::ServerKey(clone_into_array(data))),
        TagId::VER => {
            let mut versions = vec![];
            for i in 0..data.len() / 4 {
                let offset = i * 4;
                versions.push(u32::from_le_bytes(clone_into_array(
                    &data[offset..offset + 4],
                )));
            }
            Ok(Tag::Version(versions))
        }
        TagId::NONC => Ok(Tag::Nonce(clone_into_array(data))),
        TagId::DELE => {
            let tags = parse_roughtime_message(data)?;
            let mut public_key = None;
            let mut min_time = None;
            let mut max_time = None;
            for tag in tags {
                match tag {
                    Tag::PublicKey(key) => public_key = Some(key),
                    Tag::MinTime(time) => min_time = Some(time),
                    Tag::MaxTime(time) => max_time = Some(time),
                    _ => return Err(ParseError::UnexpectedTag(tag)),
                }
            }

            let Some(public_key) = public_key else {
                return Err(ParseError::MissingTag(TagId::PUBK));
            };

            let Some(min_time) = min_time else {
                return Err(ParseError::MissingTag(TagId::MINT));
            };

            let Some(max_time) = max_time else {
                return Err(ParseError::MissingTag(TagId::MAXT));
            };
            Ok(Tag::DelegatedKey(DelegatedKey {
                public_key,
                min_time,
                max_time,
            }))
        }
        TagId::PATH => {
            let mut paths = vec![];
            for i in 0..data.len() / 32 {
                let offset = i * 32;
                let mut path = [0; 32];
                path.copy_from_slice(&data[offset..offset + 32]);
                paths.push(path);
            }
            Ok(Tag::Path(paths))
        }
        TagId::RADI => Ok(Tag::Radius(u32::from_le_bytes(clone_into_array(data)))),
        TagId::PUBK => Ok(Tag::PublicKey(clone_into_array(data))),
        TagId::MIDP => Ok(Tag::Midpoint(RoughTimestamp(u64::from_le_bytes(
            clone_into_array(data),
        )))),
        TagId::SREP => {
            let tags = parse_roughtime_message(data)?;
            let mut root = None;
            let mut midpoint = None;
            let mut radius = None;
            for tag in tags {
                match tag {
                    Tag::Root(key) => root = Some(key),
                    Tag::Midpoint(time) => midpoint = Some(time),
                    Tag::Radius(r) => radius = Some(r),
                    _ => return Err(ParseError::UnexpectedTag(tag)),
                }
            }

            let Some(root) = root else {
                return Err(ParseError::MissingTag(TagId::ROOT));
            };

            let Some(midpoint) = midpoint else {
                return Err(ParseError::MissingTag(TagId::MIDP));
            };

            let Some(radius) = radius else {
                return Err(ParseError::MissingTag(TagId::RADI));
            };
            Ok(Tag::ServerResponse(ServerResponse {
                root,
                midpoint,
                radius,
            }))
        }
        TagId::MINT => Ok(Tag::MinTime(RoughTimestamp(u64::from_le_bytes(
            clone_into_array(data),
        )))),
        TagId::ROOT => Ok(Tag::Root(clone_into_array(data))),
        TagId::CERT => {
            let tags = parse_roughtime_message(data)?;
            let mut delegated = None;
            let mut signature = None;
            for tag in tags {
                match tag {
                    Tag::DelegatedKey(key) => delegated = Some(key),
                    Tag::Signature(sig) => signature = Some(sig),
                    _ => return Err(ParseError::UnexpectedTag(tag)),
                }
            }

            let Some(delegated) = delegated else {
                return Err(ParseError::MissingTag(TagId::DELE));
            };

            let Some(signature) = signature else {
                return Err(ParseError::MissingTag(TagId::SIG));
            };

            Ok(Tag::Certificate(Certificate {
                delegated,
                signature,
            }))
        }
        TagId::MAXT => Ok(Tag::MaxTime(RoughTimestamp(u64::from_le_bytes(
            clone_into_array(data),
        )))),
        TagId::INDX => Ok(Tag::Index(u32::from_le_bytes(clone_into_array(data)))),
        TagId::ZZZZ => {
            for b in data {
                if *b != 0 {
                    return Err(ParseError::ZeroesNotZero);
                }
            }
            Ok(Tag::Zeroes(data.len()))
        }
    }
}

fn parse_roughtime_message(data: &[u8]) -> Result<Vec<Tag>, ParseError> {
    let numpairs = u32::from_le_bytes(clone_into_array(&data[0..4])) as usize;
    let offsets = {
        let mut offsets = vec![];
        if numpairs > 0 {
            offsets.push(0);
            for i in 0..numpairs - 1 {
                let offset = 4 + i * 4;
                offsets.push(u32::from_le_bytes(clone_into_array(&data[offset..offset + 4])) as usize);
            }
        }

        offsets
    };

    let tagoffset = numpairs * 4;

    let tags = {
        let mut tags = vec![];
        for i in 0..numpairs {
            let offset = tagoffset + i * 4;
            tags.push(u32::from_le_bytes(clone_into_array(
                &data[offset..offset + 4],
            )));
        }

        tags
    };

    let value_offset = numpairs * 8;
    let values = &data[value_offset..];
    let mut parsed_tags = vec![];
    let mut iter = tags.into_iter().zip(offsets.into_iter()).peekable();
    while let Some((tag, offset)) = iter.next() {
        let next_offset = iter
            .peek()
            .map(|(_, offset)| *offset)
            .unwrap_or(values.len());
        let tag_data = &values[offset..next_offset];
        parsed_tags.push(parse_roughtime_tag(tag, tag_data)?);
    }

    Ok(parsed_tags)
}

async fn parse_roughtime_packet<R>(reader: &mut R) -> Result<Vec<Tag>, ParseError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    // check the header
    let mut header = [0; 8];
    reader.read_exact(&mut header).await?;
    if u64::from_le_bytes(header) != HEADER {
        return Err(ParseError::InvalidHeader);
    }

    // get the size of the packet
    let mut size_bytes = [0; 4];
    reader.read_exact(&mut size_bytes).await?;
    let size = u32::from_le_bytes(size_bytes) as usize;

    // read the packet
    let mut buf = vec![0; size];
    reader.read_exact(&mut buf).await?;

    let tags = parse_roughtime_message(&buf)?;


    Ok(tags)
}

fn padding_byte_count(body_size: usize, num_tags: usize) -> Option<usize> {
    if body_size < MIN_BODY_SIZE {
        // determine how much padding is needed to reach the minimum packet size
        let padding = MIN_BODY_SIZE - body_size;

        // compensate for additional offset and tag
        let offset_and_tag_size = if num_tags > 0 { 8 } else { 4 };
        let padding = padding.saturating_sub(offset_and_tag_size);

        Some(padding)
    } else {
        None
    }
}

async fn write_roughtime_message<W>(
    writer: &mut W,
    tags: &[Tag],
    padding_size: Option<usize>,
) -> Result<(), std::io::Error>
where
    W: tokio::io::AsyncWrite + std::fmt::Debug + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // pre-determine the offsets for all tags
    let mut offsets = vec![];
    let mut total_value_size = tags.first().map(|t| t.value_size()).unwrap_or(0);
    for t in tags.iter().skip(1) {
        offsets.push(total_value_size);
        total_value_size += t.value_size();
    }

    // write the number of tags
    writer
        .write_u32_le(tags.len() as u32 + if padding_size.is_some() { 1 } else { 0 })
        .await?;

    // write the offsets
    for offset in offsets {
        writer.write_u32_le(offset as u32).await?;
    }

    // write the additional padding offset if added and it won't be at index zero
    if padding_size.is_some() && tags.len() > 0 {
        writer.write_u32_le(total_value_size as u32).await?;
    }

    // write the tags
    for tag in tags {
        writer.write_u32_le(u32::from(tag.id())).await?;
    }

    // write the padding tag if needed
    if padding_size.is_some() {
        writer.write_u32_le(u32::from(TagId::ZZZZ)).await?;
    }

    // write the values
    for tag in tags {
        tag.write_value(writer).await?;
    }

    // write the padding if needed
    if let Some(padding_size) = padding_size {
        Tag::Zeroes(padding_size).write_value(writer).await?;
    }

    Ok(())
}

async fn write_roughtime_packet<W>(writer: &mut W, tags: &[Tag]) -> Result<(), std::io::Error>
where
    W: tokio::io::AsyncWrite + std::fmt::Debug + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // write the header
    writer.write_u64_le(HEADER).await?;

    // determine message value size and write it
    let body_size = tags.iter().map(|t| t.value_size() + 8).sum::<usize>();
    let padding: Option<usize> = padding_byte_count(body_size, tags.len());
    let padding_size = padding.map(|s| s + if tags.len() == 0 { 4 } else { 8 }).unwrap_or(0);
    let final_body_size = body_size + padding_size;
    writer.write_u32_le(final_body_size as u32).await?;

    // write message
    write_roughtime_message(writer, tags, padding).await?;

    Ok(())
}

#[derive(Debug)]
enum RoughError {
    IoError(std::io::Error),
    ParseError(ParseError),
}

impl From<std::io::Error> for RoughError {
    fn from(value: std::io::Error) -> Self {
        RoughError::IoError(value)
    }
}

impl From<ParseError> for RoughError {
    fn from(value: ParseError) -> Self {
        RoughError::ParseError(value)
    }
}

const MAX_PACKET_SIZE: usize = 1280;

fn rough_hash(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;

    let mut hasher = sha2::Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0; 32];
    hash.copy_from_slice(&result[0..32]);
    hash
}

#[tokio::main]
async fn main() -> Result<(), RoughError> {
    // setup root signing key for server
    // this key should normally only be used to get a signed delegated key (completely offline)
    let mut signing_key = {
        let key_data = BASE64_STANDARD
            .decode("XBPDZPf5Ky9eYBDwfwUgYQ8m2GhsObGso0K6zFMaI4Q=")
            .unwrap();
        let mut key = [0; 32];
        key.copy_from_slice(&key_data);
        SigningKey::from_bytes(&key)
    };
    let verifying_key = signing_key.verifying_key();
    println!(
        "Public key: {}",
        BASE64_STANDARD.encode(verifying_key.to_bytes())
    );

    // create bytes to sign (i.e. context string with value of delegatedkey appended to it)
    let mut buff = vec![0xff];
    buff.extend_from_slice(verifying_key.as_bytes());
    let verifying_key_hash = rough_hash(&buff);

    // create delegated key
    let mut delegated_key = SigningKey::generate(&mut OsRng);
    let delegated_public_key = delegated_key.verifying_key();

    // create validity for delegated key
    let delegation = DelegatedKey {
        public_key: delegated_public_key.to_bytes(),
        min_time: RoughTimestamp::now(),
        max_time: RoughTimestamp::now() + Duration::from_secs(3600 * 24),
    };

    // create bytes to sign (i.e. context string with value of delegatedkey appended to it)
    let mut buff = vec![];
    buff.extend_from_slice(ROUGHTIME_DELEGATION_CONTEXT_STRING.as_bytes());
    let curr_buff_size = buff.len() as u64;
    let mut cursor = std::io::Cursor::new(&mut buff);
    cursor.set_position(curr_buff_size);
    Tag::DelegatedKey(delegation.clone())
        .write_value(&mut cursor)
        .await?;

    // sign delegated key with root key
    let signature = signing_key.sign(&buff);
    let certificate = Certificate {
        delegated: delegation,
        signature: Signature(signature.to_bytes()),
    };

    // create socket for server
    let server = tokio::net::UdpSocket::bind("127.0.0.1:2002").await?;
    let mut buf = vec![0; MAX_PACKET_SIZE];

    loop {
        println!("Waiting for next packet to be received");
        let (len, addr) = server.recv_from(&mut buf).await?;
        println!("Received a packet of size {len}");
        let packet = &mut buf[0..len];
        println!("Reading roughtime packet from buffer");
        let packet_data = parse_roughtime_packet(&mut std::io::Cursor::new(&mut *packet)).await?;
        println!("Found {} fields in roughtime packet", packet_data.len());
        println!("{packet_data:?}");
        let request = RoughRequest::from_tags(&packet_data)?;
        println!("Got a request: {request:?}");

        // check if the server key matches our key
        match request.server_key {
            Some(server_key) => {
                if server_key != verifying_key_hash {
                    println!("Server key does not match, ignoring");
                    continue;
                }
            }
            None => {
                println!("Server key not provided, using our current key");
            }
        }

        println!("Generating response");

        let data = {
            let mut tmp = [0; 33];
            tmp[1..].copy_from_slice(&request.nonce);
            tmp
        };

        let root = rough_hash(&data);
        let server_response = ServerResponse {
            root,
            midpoint: RoughTimestamp::now(),
            radius: 3,
        };

        let mut srep_buff = vec![];
        srep_buff.extend_from_slice(ROUGHTIME_RESPONSE_CONTEXT_STRING.as_bytes());
        let curr_srep_buff_size = srep_buff.len() as u64;
        let mut srep_cursor = std::io::Cursor::new(&mut srep_buff);
        srep_cursor.set_position(curr_srep_buff_size);
        Tag::ServerResponse(server_response.clone())
            .write_value(&mut srep_cursor)
            .await?;
        let sig = delegated_key.sign(&srep_buff);
        let signature = Signature(sig.to_bytes());

        let response = RoughResponse {
            signature,
            version: SUPPORTED_VERSION,
            nonce: request.nonce,
            path: vec![],
            server_response,
            certificate,
            index: 0
        };

        println!("Converting response back to message: {response:?}");
        let response_tags = response.into_tags();

        println!("Writing packet data back");
        let mut cursor = std::io::Cursor::new(&mut *packet);
        write_roughtime_packet(&mut cursor, &response_tags).await?;
        let bytes_written = cursor.position() as usize;
        println!("Wrote {bytes_written} bytes back into buffer");
        let bytes_sent = server.send_to(&buf[0..bytes_written], addr).await?;
        println!("Responded back to requesting address with {bytes_sent} bytes");
    }
}k


#[cfg(test)]
mod tests {
    use std::{io::Cursor, vec};

    use super::*;

    #[tokio::test]
    async fn test_tag_serialization_size() {
        async fn test_tag_size(tag: Tag) {
            let mut buf = vec![];
            tag.write_value(&mut Cursor::new(&mut buf)).await.unwrap();
            assert_eq!(buf.len(), tag.value_size());
        }

        test_tag_size(Tag::Version(vec![0])).await;
        test_tag_size(Tag::Version(vec![0, 1, 2, 3])).await;
        test_tag_size(Tag::Nonce([0; 32])).await;
        test_tag_size(Tag::ServerKey([0; 32])).await;
        test_tag_size(Tag::Signature(Signature([0; 64]))).await;
        test_tag_size(Tag::Path(vec![[0; 32]])).await;
        test_tag_size(Tag::Path(vec![])).await;
        test_tag_size(Tag::Path(vec![[0; 32], [0; 32], [0; 32]])).await;
        test_tag_size(Tag::ServerResponse(ServerResponse {
            root: [0; 32],
            midpoint: RoughTimestamp(0),
            radius: 0,
        })).await;
        test_tag_size(Tag::Certificate(Certificate {
            delegated: DelegatedKey {
                public_key: [0; 32],
                min_time: RoughTimestamp(0),
                max_time: RoughTimestamp(0),
            },
            signature: Signature([0; 64]),
        })).await;
        test_tag_size(Tag::Index(0)).await;
        test_tag_size(Tag::DelegatedKey(DelegatedKey {
            public_key: [0; 32],
            min_time: RoughTimestamp(0),
            max_time: RoughTimestamp(0),
        })).await;
        test_tag_size(Tag::PublicKey([0; 32])).await;
        test_tag_size(Tag::Midpoint(RoughTimestamp(0))).await;
        test_tag_size(Tag::Radius(0)).await;
        test_tag_size(Tag::MinTime(RoughTimestamp(0))).await;
        test_tag_size(Tag::MaxTime(RoughTimestamp(0))).await;
        test_tag_size(Tag::Root([0; 32])).await;
        test_tag_size(Tag::Zeroes(0)).await;
        test_tag_size(Tag::Zeroes(32)).await;
    }

    #[tokio::test]
    async fn test_message_serialization() {
        let tags = vec![];
        let mut buf = vec![];
        write_roughtime_message(&mut Cursor::new(&mut buf), &tags, None).await.unwrap();
        assert_eq!(buf.len(), 4);
        assert_eq!(tags, parse_roughtime_message(&buf).unwrap());

        let tags = vec![
            Tag::Version(vec![0]),
        ];
        let mut buf = vec![];
        write_roughtime_message(&mut Cursor::new(&mut buf), &tags, None).await.unwrap();
        assert_eq!(buf.len(), 12);
        assert_eq!(tags, parse_roughtime_message(&buf).unwrap());

        let tags = vec![
            Tag::Version(vec![0]),
            Tag::Radius(0),
        ];
        let mut buf = vec![];
        write_roughtime_message(&mut Cursor::new(&mut buf), &tags, None).await.unwrap();
        assert_eq!(buf.len(), 24);
        assert_eq!(tags, parse_roughtime_message(&buf).unwrap());

        let tags = vec![];
        let mut buf = vec![];
        write_roughtime_message(&mut Cursor::new(&mut buf), &tags, Some(8)).await.unwrap();
        assert_eq!(buf.len(), 16);

        let tags = vec![
            Tag::Version(vec![0]),
        ];
        write_roughtime_message(&mut Cursor::new(&mut buf), &tags, Some(8)).await.unwrap();
        assert_eq!(buf.len(), 28);

        let tags = vec![
            Tag::Version(vec![0]),
            Tag::Radius(0),
        ];
        write_roughtime_message(&mut Cursor::new(&mut buf), &tags, Some(0)).await.unwrap();
        assert_eq!(buf.len(), 32);
    }

    #[tokio::test]
    async fn test_packet_serialization() {
        // a lot of padding zeroes needed
        let tags = vec![Tag::Version(vec![0])];
        let mut buf: Vec<u8> = vec![];
        write_roughtime_packet(&mut Cursor::new(&mut buf), &tags).await.unwrap();
        assert_eq!(buf.len(), 1024);
        let parsed = parse_roughtime_packet(&mut Cursor::new(&buf)).await.unwrap();
        assert_eq!(parsed.len(), 2);

        // no padding zeroes needed
        let tags = vec![Tag::Version(vec![0; 251])];
        let mut buf: Vec<u8> = vec![];
        write_roughtime_packet(&mut Cursor::new(&mut buf), &tags).await.unwrap();
        assert_eq!(buf.len(), 1024);
        let parsed = parse_roughtime_packet(&mut Cursor::new(&buf)).await.unwrap();
        assert_eq!(parsed, tags);

        // too short, padding zeroes make message a little larger
        let tags = vec![Tag::Version(vec![0; 250])];
        let mut buf: Vec<u8> = vec![];
        write_roughtime_packet(&mut Cursor::new(&mut buf), &tags).await.unwrap();
        assert_eq!(buf.len(), 1028);
        let parsed = parse_roughtime_packet(&mut Cursor::new(&buf)).await.unwrap();
        assert!(matches!(parsed[1], Tag::Zeroes(0)));

        // too short, but no padding zeroes needed
        let tags = vec![Tag::Version(vec![0; 249])];
        let mut buf: Vec<u8> = vec![];
        write_roughtime_packet(&mut Cursor::new(&mut buf), &tags).await.unwrap();
        assert_eq!(buf.len(), 1024);
        let parsed = parse_roughtime_packet(&mut Cursor::new(&buf)).await.unwrap();
        assert!(matches!(parsed[1], Tag::Zeroes(0)));

        // just a little short, some padding zeroes needed
        let tags = vec![Tag::Version(vec![0; 248])];
        let mut buf: Vec<u8> = vec![];
        write_roughtime_packet(&mut Cursor::new(&mut buf), &tags).await.unwrap();
        assert_eq!(buf.len(), 1024);
        let parsed = parse_roughtime_packet(&mut Cursor::new(&buf)).await.unwrap();
        assert!(matches!(parsed[1], Tag::Zeroes(4)));
    }

    #[test]
    fn test_padding_size() {
        let res = padding_byte_count(0, 0).unwrap();
        assert_eq!(res, 1008);

        let res = padding_byte_count(4, 1).unwrap();
        assert_eq!(res, 1000);

        let res = padding_byte_count(12, 2).unwrap();
        assert_eq!(res, 992);

        let res = padding_byte_count(1024, 6);
        assert!(matches!(res, None));

        let res = padding_byte_count(1010, 6).unwrap();
        assert_eq!(res, 0);
    }
}
