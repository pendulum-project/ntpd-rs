const HEADER: u64 = 0x4d49544847554f52;

const MIN_PACKET_SIZE: usize = 1024;

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

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
struct RoughTimestamp(pub u64);

#[derive(Debug, Clone, Copy)]
struct Signature([u8; 64]);

#[derive(Debug, Clone, Copy)]
struct ServerResponse {
    root: [u8; 32],
    midpoint: RoughTimestamp,
    radius: u32,
}

#[derive(Debug, Clone, Copy)]
struct DelegatedKey {
    publicKey: [u8; 32],
    minTime: RoughTimestamp,
    maxTime: RoughTimestamp,
}

#[derive(Debug, Clone, Copy)]
struct Certificate {
    delegated: DelegatedKey,
    signature: Signature,
}

#[derive(Debug, Clone)]
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
            field_count * 8
        }

        match self {
            Tag::Version(versions) => versions.len() * 4,
            Tag::Nonce(_) => 32,
            Tag::ServerKey(_) => 32,
            Tag::Signature(_) => 64,
            Tag::Path(paths) => paths.len() * 32,
            Tag::ServerResponse(_) => size_of_header(3) + 32 + 8 + 4,
            Tag::Certificate(_) => size_of_header(2) + size_of_header(3) + 32 + 8 + 4 + 64,
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

    async fn write_value<W>(&self, writer: &mut W) -> Result<usize, std::io::Error> where W: tokio::io::AsyncWrite + Unpin {
        use tokio::io::AsyncWriteExt;

        let mut bytes_written = 0;

        match self {
            Tag::Version(vec) => {
                for v in vec {
                    writer.write_all(&v.to_le_bytes()).await?;
                    bytes_written += 4;
                }
            },
            Tag::Nonce(n) => {
                writer.write_all(n).await?;
                bytes_written += n.len();
            },
            Tag::ServerKey(sk) => {
                writer.write_all(sk).await?;
                bytes_written += sk.len();
            },
            Tag::Signature(signature) => {
                writer.write_all(&signature.0).await?;
                bytes_written += signature.0.len();
            },
            Tag::Path(vec) => {
                for v in vec {
                    writer.write_all(v).await?;
                    bytes_written += v.len();
                }
            },
            Tag::ServerResponse(server_response) => {
                let tags = [
                    Tag::Root(server_response.root),
                    Tag::Midpoint(server_response.midpoint),
                    Tag::Radius(server_response.radius),
                ];
                bytes_written += Box::pin(write_roughtime_message(writer, &tags, false)).await?;
            },
            Tag::Certificate(certificate) => {
                let tags = [
                    Tag::DelegatedKey(certificate.delegated),
                    Tag::Signature(certificate.signature),
                ];
                bytes_written += Box::pin(write_roughtime_message(writer, &tags, false)).await?;
            },
            Tag::Index(idx) => {
                writer.write_u32_le(*idx).await?;
                bytes_written += 4;
            },
            Tag::DelegatedKey(delegated_key) => {
                let tags = [
                    Tag::PublicKey(delegated_key.publicKey),
                    Tag::MinTime(delegated_key.minTime),
                    Tag::MaxTime(delegated_key.maxTime),
                ];
                bytes_written += Box::pin(write_roughtime_message(writer, &tags, false)).await?;
            },
            Tag::PublicKey(pk) => {
                writer.write_all(pk).await?;
                bytes_written += pk.len();
            },
            Tag::Midpoint(rough_timestamp) => {
                writer.write_all(&rough_timestamp.0.to_le_bytes()).await?;
                bytes_written += 8;
            },
            Tag::Radius(r) => {
                writer.write_u32_le(*r).await?;
                bytes_written += 4;
            },
            Tag::MinTime(rough_timestamp) => {
                writer.write_all(&rough_timestamp.0.to_le_bytes()).await?;
                bytes_written += 8;
            },
            Tag::MaxTime(rough_timestamp) => {
                writer.write_all(&rough_timestamp.0.to_le_bytes()).await?;
                bytes_written += 8;
            },
            Tag::Root(root) => {
                writer.write_all(root).await?;
                bytes_written += root.len();
            },
            Tag::Zeroes(size) => {
                for _ in 0..*size {
                    writer.write_u8(0).await?;
                    bytes_written += 1;
                }
            },
        }

        Ok(bytes_written)
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
    where A: Sized + Default + AsMut<[T]>,
          T: Clone
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
        },
        TagId::SRV => {
            Ok(Tag::ServerKey(clone_into_array(data)))
        },
        TagId::VER => {
            let mut versions = vec![];
            for i in 0..data.len() / 4 {
                let offset = i * 4;
                versions.push(u32::from_le_bytes(clone_into_array(&data[offset..offset + 4])));
            }
            Ok(Tag::Version(versions))
        },
        TagId::NONC => {
            Ok(Tag::Nonce(clone_into_array(data)))
        },
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
                    _ => { return Err(ParseError::UnexpectedTag(tag))},
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
                publicKey: public_key,
                minTime: min_time,
                maxTime: max_time,
            }))
        },
        TagId::PATH => {
            let mut paths = vec![];
            for i in 0..data.len() / 32 {
                let offset = i * 32;
                let mut path = [0; 32];
                path.copy_from_slice(&data[offset..offset + 32]);
                paths.push(path);
            }
            Ok(Tag::Path(paths))
        },
        TagId::RADI => {
            Ok(Tag::Radius(u32::from_le_bytes(clone_into_array(data))))
        },
        TagId::PUBK => {
            Ok(Tag::PublicKey(clone_into_array(data)))
        },
        TagId::MIDP => {
            Ok(Tag::Midpoint(RoughTimestamp(u64::from_le_bytes(clone_into_array(data)))))
        },
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
                    _ => { return Err(ParseError::UnexpectedTag(tag))},
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
        },
        TagId::MINT => {
            Ok(Tag::MinTime(RoughTimestamp(u64::from_le_bytes(clone_into_array(data)))))
        },
        TagId::ROOT => {
            Ok(Tag::Root(clone_into_array(data)))
        },
        TagId::CERT => {
            let tags = parse_roughtime_message(data)?;
            let mut delegated = None;
            let mut signature = None;
            for tag in tags {
                match tag {
                    Tag::DelegatedKey(key) => delegated = Some(key),
                    Tag::Signature(sig) => signature = Some(sig),
                    _ => { return Err(ParseError::UnexpectedTag(tag))},
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
        },
        TagId::MAXT => {
            Ok(Tag::MaxTime(RoughTimestamp(u64::from_le_bytes(clone_into_array(data)))))
        },
        TagId::INDX => {
            Ok(Tag::Index(u32::from_le_bytes(clone_into_array(data))))
        },
        TagId::ZZZZ => {
            for b in data {
                if *b != 0 {
                    return Err(ParseError::ZeroesNotZero);
                }
            }
            Ok(Tag::Zeroes(data.len()))
        },
    }
}

fn parse_roughtime_message(data: &[u8]) -> Result<Vec<Tag>, ParseError> {
    let numpairs = u32::from_le_bytes(clone_into_array(&data[0..4])) as usize;
    dbg!(&numpairs);
    let offsets = {
        let mut offsets = vec![];
        offsets.push(0);
        for i in 0..numpairs - 1 {
            let offset = 4 + i * 4;
            offsets.push(u32::from_le_bytes(clone_into_array(&data[offset..offset + 4])) as usize);
        }

        offsets
    };

    let tagoffset = numpairs * 4;

    let tags = {
        let mut tags = vec![];
        for i in 0..numpairs {
            let offset = tagoffset + i * 4;
            tags.push(u32::from_le_bytes(clone_into_array(&data[offset..offset + 4])));
        }

        tags
    };

    let value_offset = numpairs * 8;
    let values = &data[value_offset..];
    let mut parsed_tags = vec![];
    let mut iter = tags.into_iter().zip(offsets.into_iter()).peekable();
    while let Some((tag, offset)) = iter.next() {
        let next_offset = iter.peek().map(|(_, offset)| *offset).unwrap_or(values.len());
        let tag_data = &values[offset..next_offset];
        parsed_tags.push(parse_roughtime_tag(tag, tag_data)?);
    }

    Ok(parsed_tags)
}

async fn read_roughtime_packet<R>(reader: &mut R) -> Result<Vec<Tag>, ParseError> where R: tokio::io::AsyncRead + Unpin {
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

    parse_roughtime_message(&buf)
}

async fn write_roughtime_message<W>(writer: &mut W, tags: &[Tag], pad_with_zeroes: bool) -> Result<usize, std::io::Error> where W: tokio::io::AsyncWrite + Unpin {
    use tokio::io::AsyncWriteExt;

    let mut bytes_written = 0;

    // pre-determine the offsets for all tags
    let mut offsets = vec![];
    let mut total_value_size = 0;
    for t in tags.iter() {
        offsets.push(total_value_size);
        total_value_size += t.value_size();
    }
    // remove the first offset, since it's always zero
    offsets.remove(0);

    // determine if any padding is needed
    let padding_size = if pad_with_zeroes {
        let packet_size = 8 + 8 * tags.len() + total_value_size;
        if packet_size < MIN_PACKET_SIZE {
            // determine how much padding is needed to reach the minimum packet size
            let padding = MIN_PACKET_SIZE - packet_size;

            // compensate for additional offset and tag
            let padding = if padding < 8 {
                0
            } else {
                padding - 8
            };

            Some(padding)
        } else {
            None
        }
    } else {
        None
    };


    // write the number of tags
    writer.write_u32_le(tags.len() as u32 + if padding_size.is_some() {
        1
    } else {
        0
    }).await?;
    bytes_written += 4;

    // write the offsets
    for offset in offsets {
        writer.write_u32_le(offset as u32).await?;
        bytes_written += 4;
    }

    // write the additional padding offset if added
    if padding_size.is_some() {
        writer.write_u32_le(total_value_size as u32).await?;
        bytes_written += 4;
    }

    // write the tags
    for tag in tags {
        writer.write_u32_le(u32::from(tag.id())).await?;
        bytes_written += 4;
    }

    // write the padding tag if needed
    if padding_size.is_some() {
        writer.write_u32_le(u32::from(TagId::ZZZZ)).await?;
        bytes_written += 4;
    }

    // write the values
    for tag in tags {
        bytes_written += tag.write_value(writer).await?;
    }

    // write the padding if needed
    if let Some(padding_size) = padding_size {
        bytes_written += Tag::Zeroes(padding_size).write_value(writer).await?;
    }

    Ok(bytes_written)
}

async fn write_roughtime_packet<W>(writer: &mut W, tags: &[Tag]) -> Result<usize, std::io::Error> where W: tokio::io::AsyncWrite + Unpin {
    use tokio::io::AsyncWriteExt;

    let mut bytes_written = 0;

    // write the header
    writer.write_all(&HEADER.to_le_bytes()).await?;
    bytes_written += std::mem::size_of_val(&HEADER);

    // determine message size and write it
    let body_size = tags.iter().map(|t| t.value_size() + 8).sum::<usize>() as u32;
    writer.write_u32_le(body_size).await?;
    bytes_written += 4;

    // write message
    bytes_written += write_roughtime_message(writer, tags, true).await?;

    Ok(bytes_written)
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

#[tokio::main]
async fn main() -> Result<(), RoughError> {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:2002").await?;
    let mut buf = vec![0; MAX_PACKET_SIZE];

    loop {
        println!("Waiting for next packet to be received");
        let (len, addr) = server.recv_from(&mut buf).await?;
        println!("Received a packet of size {len}");
        let packet = &mut buf[0..len];
        println!("Reading roughtime packet from buffer");
        let packet_data = read_roughtime_packet(&mut std::io::Cursor::new(&mut *packet)).await?;
        println!("Found {} fields in roughtime packet", packet_data.len());
        println!("{packet_data:?}");
        println!("Writing packet data back");
        let bytes_written = write_roughtime_packet(&mut std::io::Cursor::new(&mut *packet), &packet_data).await?;
        println!("Wrote {bytes_written} bytes back into buffer");
        let bytes_sent = server.send_to(&buf[0..bytes_written], addr).await?;
        println!("Responded back to requesting address with {bytes_sent} bytes");
    }
}
