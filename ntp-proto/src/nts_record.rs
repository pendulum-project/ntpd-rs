use std::io::{Read, Write};

#[derive(Debug)]
pub enum WriteError {
    Invalid,
    TooLong,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("Invalid NTS-KE record"),
            Self::TooLong => f.write_str("NTS-KE record too long"),
        }
    }
}

impl std::error::Error for WriteError {}

impl NtsRecord {
    fn record_type(&self) -> u16 {
        match self {
            NtsRecord::EndOfMessage => 0,
            NtsRecord::NextProtocol { .. } => 1,
            NtsRecord::Error { .. } => 2,
            NtsRecord::Warning { .. } => 3,
            NtsRecord::AeadAlgorithm { .. } => 4,
            NtsRecord::NewCookie { .. } => 5,
            NtsRecord::Server { .. } => 6,
            NtsRecord::Port { .. } => 7,
            NtsRecord::Unknown { record_type, .. } => record_type & !0x8000,
        }
    }

    fn is_critical(&self) -> bool {
        match self {
            NtsRecord::EndOfMessage => true,
            NtsRecord::NextProtocol { .. } => true,
            NtsRecord::Error { .. } => true,
            NtsRecord::Warning { .. } => true,
            NtsRecord::AeadAlgorithm { critical, .. } => *critical,
            NtsRecord::NewCookie { .. } => false,
            NtsRecord::Server { critical, .. } => *critical,
            NtsRecord::Port { critical, .. } => *critical,
            NtsRecord::Unknown { critical, .. } => *critical,
        }
    }

    fn validate(&self) -> std::io::Result<()> {
        match self {
            NtsRecord::Unknown {
                record_type, data, ..
            } => {
                if *record_type & 0x8000 != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        WriteError::Invalid,
                    ));
                }
                if data.len() > u16::MAX as usize {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        WriteError::TooLong,
                    ));
                }
            }
            NtsRecord::NextProtocol { protocol_ids } => {
                if protocol_ids.len() >= (u16::MAX as usize) / 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        WriteError::TooLong,
                    ));
                }
            }

            NtsRecord::AeadAlgorithm { algorithm_ids, .. } => {
                if algorithm_ids.len() >= (u16::MAX as usize) / 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        WriteError::TooLong,
                    ));
                }
            }
            NtsRecord::NewCookie { cookie_data } => {
                if cookie_data.len() > u16::MAX as usize {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        WriteError::TooLong,
                    ));
                }
            }
            NtsRecord::Server { name, .. } => {
                if name.as_bytes().len() >= (u16::MAX as usize) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        WriteError::TooLong,
                    ));
                }
            }

            _ => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum NtsRecord {
    EndOfMessage,
    NextProtocol {
        protocol_ids: Vec<u16>,
    },
    Error {
        errorcode: u16,
    },
    Warning {
        warningcode: u16,
    },
    AeadAlgorithm {
        critical: bool,
        algorithm_ids: Vec<u16>,
    },
    NewCookie {
        cookie_data: Vec<u8>,
    },
    Server {
        critical: bool,
        name: String,
    },
    Port {
        critical: bool,
        port: u16,
    },
    Unknown {
        record_type: u16,
        critical: bool,
        data: Vec<u8>,
    },
}

fn read_u16_be(reader: &mut impl Read) -> std::io::Result<u16> {
    let mut bytes = [0, 0];
    reader.read_exact(&mut bytes)?;

    Ok(u16::from_be_bytes(bytes))
}

fn read_u16s_be(reader: &mut impl Read, length: usize) -> std::io::Result<Vec<u16>> {
    (0..length).map(|_| read_u16_be(reader)).collect()
}

fn read_bytes_exact(reader: &mut impl Read, length: usize) -> std::io::Result<Vec<u8>> {
    let mut output = vec![0; length];
    reader.read_exact(&mut output)?;

    Ok(output)
}

impl NtsRecord {
    pub async fn async_read<A: tokio::io::AsyncReadExt + std::marker::Unpin>(
        reader: &mut A,
    ) -> std::io::Result<NtsRecord> {
        let raw_record_type = reader.read_u16().await?;
        let critical = raw_record_type & 0x8000 != 0;
        let record_type = raw_record_type & !0x8000;
        let record_len = reader.read_u16().await? as usize;

        Ok(match record_type {
            0 if record_len == 0 && critical => NtsRecord::EndOfMessage,
            1 if record_len % 2 == 0 && critical => {
                let n_protocols = record_len / 2;

                let mut protocol_ids = Vec::with_capacity(n_protocols);
                for _ in 0..n_protocols {
                    protocol_ids.push(reader.read_u16().await?);
                }

                NtsRecord::NextProtocol { protocol_ids }
            }
            2 if record_len == 2 && critical => NtsRecord::Error {
                errorcode: reader.read_u16().await?,
            },
            3 if record_len == 2 && critical => NtsRecord::Warning {
                warningcode: reader.read_u16().await?,
            },
            4 if record_len % 2 == 0 => {
                let n_algorithms = record_len / 2;

                let mut algorithm_ids = Vec::with_capacity(n_algorithms);
                for _ in 0..n_algorithms {
                    algorithm_ids.push(reader.read_u16().await?);
                }

                NtsRecord::AeadAlgorithm {
                    critical,
                    algorithm_ids,
                }
            }
            5 if !critical => {
                let mut cookie_data = vec![0; record_len];
                reader.read_exact(&mut cookie_data).await?;
                NtsRecord::NewCookie { cookie_data }
            }
            6 => {
                let mut str_data = vec![0; record_len];
                reader.read_exact(&mut str_data).await?;
                match String::from_utf8(str_data) {
                    Ok(name) => NtsRecord::Server { critical, name },
                    Err(e) => NtsRecord::Unknown {
                        record_type,
                        critical,
                        data: e.into_bytes(),
                    },
                }
            }
            7 if record_len == 2 => NtsRecord::Port {
                critical,
                port: reader.read_u16().await?,
            },
            _ => {
                let mut data = vec![0; record_len];
                reader.read_exact(&mut data).await?;

                NtsRecord::Unknown {
                    record_type,
                    critical,
                    data,
                }
            }
        })
    }

    pub fn read<A: Read>(reader: &mut A) -> std::io::Result<NtsRecord> {
        let raw_record_type = read_u16_be(reader)?;
        let critical = raw_record_type & 0x8000 != 0;
        let record_type = raw_record_type & !0x8000;
        let record_len = read_u16_be(reader)? as usize;

        Ok(match record_type {
            0 if record_len == 0 && critical => NtsRecord::EndOfMessage,
            1 if record_len % 2 == 0 && critical => {
                let n_protocols = record_len / 2;
                let protocol_ids = read_u16s_be(reader, n_protocols)?;
                NtsRecord::NextProtocol { protocol_ids }
            }
            2 if record_len == 2 && critical => NtsRecord::Error {
                errorcode: read_u16_be(reader)?,
            },
            3 if record_len == 2 && critical => NtsRecord::Warning {
                warningcode: read_u16_be(reader)?,
            },
            4 if record_len % 2 == 0 => {
                let n_algorithms = record_len / 2;
                let algorithm_ids = read_u16s_be(reader, n_algorithms)?;
                NtsRecord::AeadAlgorithm {
                    critical,
                    algorithm_ids,
                }
            }
            5 if !critical => {
                let cookie_data = read_bytes_exact(reader, record_len)?;
                NtsRecord::NewCookie { cookie_data }
            }
            6 => {
                // NOTE: the string data should be ascii (not utf8) but we don't enforce that here
                let str_data = read_bytes_exact(reader, record_len)?;
                match String::from_utf8(str_data) {
                    Ok(name) => NtsRecord::Server { critical, name },
                    Err(e) => NtsRecord::Unknown {
                        record_type,
                        critical,
                        data: e.into_bytes(),
                    },
                }
            }
            7 if record_len == 2 => NtsRecord::Port {
                critical,
                port: read_u16_be(reader)?,
            },
            _ => NtsRecord::Unknown {
                record_type,
                critical,
                data: read_bytes_exact(reader, record_len)?,
            },
        })
    }

    pub fn write<A: Write>(&self, writer: &mut A) -> std::io::Result<()> {
        // error out early when the record is invalid
        self.validate()?;

        // all messages start with the record type
        let record_type = self.record_type() | ((self.is_critical() as u16) << 15);
        writer.write_all(&record_type.to_be_bytes())?;

        let size_of_u16 = std::mem::size_of::<u16>() as u16;
        match self {
            NtsRecord::EndOfMessage => {
                writer.write_all(&0_u16.to_be_bytes())?;
            }
            NtsRecord::Unknown { data, .. } => {
                writer.write_all(&(data.len() as u16).to_be_bytes())?;
                writer.write_all(data)?;
            }
            NtsRecord::NextProtocol { protocol_ids } => {
                let length = size_of_u16 * protocol_ids.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                for id in protocol_ids {
                    writer.write_all(&id.to_be_bytes())?;
                }
            }
            NtsRecord::Error { errorcode } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&errorcode.to_be_bytes())?;
            }
            NtsRecord::Warning { warningcode } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&warningcode.to_be_bytes())?;
            }
            NtsRecord::AeadAlgorithm { algorithm_ids, .. } => {
                let length = size_of_u16 * algorithm_ids.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                for id in algorithm_ids {
                    writer.write_all(&id.to_be_bytes())?;
                }
            }
            NtsRecord::NewCookie { cookie_data } => {
                let length = cookie_data.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(cookie_data)?;
            }
            NtsRecord::Server { name, .. } => {
                // NOTE: the server name should be ascii
                #[cfg(not(feature = "fuzz"))]
                debug_assert!(name.is_ascii());
                let length = name.len() as u16;
                writer.write_all(&length.to_be_bytes())?;

                writer.write_all(name.as_bytes())?;
            }
            NtsRecord::Port { port, .. } => {
                writer.write_all(&size_of_u16.to_be_bytes())?;
                writer.write_all(&port.to_be_bytes())?;
            }
        }

        Ok(())
    }

    pub async fn async_write<A: tokio::io::AsyncWriteExt + std::marker::Unpin>(
        &self,
        writer: &mut A,
    ) -> std::io::Result<()> {
        // error out early when the record is invalid
        self.validate()?;

        // all messages start with the record type
        let record_type = self.record_type() | ((self.is_critical() as u16) << 15);
        writer.write_all(&record_type.to_be_bytes()).await?;

        let size_of_u16 = std::mem::size_of::<u16>() as u16;
        match self {
            NtsRecord::EndOfMessage => {
                writer.write_all(&0_u16.to_be_bytes()).await?;
            }
            NtsRecord::Unknown { data, .. } => {
                writer.write_all(&(data.len() as u16).to_be_bytes()).await?;
                writer.write_all(data).await?;
            }
            NtsRecord::NextProtocol { protocol_ids } => {
                let length = size_of_u16 * protocol_ids.len() as u16;
                writer.write_all(&length.to_be_bytes()).await?;

                for id in protocol_ids {
                    writer.write_all(&id.to_be_bytes()).await?;
                }
            }
            NtsRecord::Error { errorcode } => {
                writer.write_all(&size_of_u16.to_be_bytes()).await?;
                writer.write_all(&errorcode.to_be_bytes()).await?;
            }
            NtsRecord::Warning { warningcode } => {
                writer.write_all(&size_of_u16.to_be_bytes()).await?;
                writer.write_all(&warningcode.to_be_bytes()).await?;
            }
            NtsRecord::AeadAlgorithm { algorithm_ids, .. } => {
                let length = size_of_u16 * algorithm_ids.len() as u16;
                writer.write_all(&length.to_be_bytes()).await?;

                for id in algorithm_ids {
                    writer.write_all(&id.to_be_bytes()).await?;
                }
            }
            NtsRecord::NewCookie { cookie_data } => {
                let length = cookie_data.len() as u16;
                writer.write_all(&length.to_be_bytes()).await?;

                writer.write_all(cookie_data).await?;
            }
            NtsRecord::Server { name, .. } => {
                let length = name.len() as u16;
                writer.write_all(&length.to_be_bytes()).await?;

                writer.write_all(name.as_bytes()).await?;
            }
            NtsRecord::Port { port, .. } => {
                writer.write_all(&size_of_u16.to_be_bytes()).await?;
                writer.write_all(&port.to_be_bytes()).await?;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "fuzz")]
impl<'a> arbitrary::Arbitrary<'a> for Record {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let record = u16::arbitrary(u)?;

        let critical = record & 0x8000 != 0;
        let record_type = record & !0x8000;

        use Record::*;
        Ok(match record_type {
            0 => EndOfMessage,
            1 => NextProtocol {
                protocol_ids: u.arbitrary()?,
            },
            2 => Error {
                errorcode: u.arbitrary()?,
            },
            3 => Warning {
                warningcode: u.arbitrary()?,
            },
            4 => AeadAlgorithm {
                critical,
                algorithm_ids: u.arbitrary()?,
            },
            5 => NewCookie {
                cookie_data: u.arbitrary()?,
            },
            6 => Server {
                critical,
                name: u.arbitrary()?,
            },
            7 => Port {
                critical,
                port: u.arbitrary()?,
            },
            _ => Record::Unknown {
                record_type,
                critical,
                data: u.arbitrary()?,
            },
        })
    }
}

#[cfg(feature = "fuzz")]
impl<'a> arbitrary::Arbitrary<'a> for NtsRecord {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let record = u16::arbitrary(u)?;

        let critical = record & 0x8000 != 0;
        let record_type = record & !0x8000;

        use NtsRecord::*;
        Ok(match record_type {
            0 => EndOfMessage,
            1 => NextProtocol {
                protocol_ids: u.arbitrary()?,
            },
            2 => Error {
                errorcode: u.arbitrary()?,
            },
            3 => Warning {
                warningcode: u.arbitrary()?,
            },
            4 => AeadAlgorithm {
                critical,
                algorithm_ids: u.arbitrary()?,
            },
            5 => NewCookie {
                cookie_data: u.arbitrary()?,
            },
            6 => Server {
                critical,
                name: u.arbitrary()?,
            },
            7 => Port {
                critical,
                port: u.arbitrary()?,
            },
            _ => NtsRecord::Unknown {
                record_type,
                critical,
                data: u.arbitrary()?,
            },
        })
    }
}
