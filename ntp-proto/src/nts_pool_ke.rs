use std::ops::ControlFlow;

use crate::{
    nts_record::{AeadAlgorithm, NtsKeys, ProtocolId},
    KeyExchangeError, NtsRecord, NtsRecordDecoder,
};

/// Pool KE decoding records reserved from an NTS KE
#[derive(Debug, Default)]
pub struct SupportedAlgorithmsDecoder {
    decoder: NtsRecordDecoder,
    supported_algorithms: Vec<(u16, u16)>,
}

impl SupportedAlgorithmsDecoder {
    #[must_use] pub fn step_with_slice(
        mut self,
        bytes: &[u8],
    ) -> ControlFlow<Result<Vec<(u16, u16)>, KeyExchangeError>, Self> {
        self.decoder.extend(bytes.iter().copied());

        loop {
            match self.decoder.step() {
                Err(e) => return ControlFlow::Break(Err(e.into())),
                Ok(Some(record)) => self = self.step_with_record(record)?,
                Ok(None) => return ControlFlow::Continue(self),
            }
        }
    }

    #[inline(always)]
    fn step_with_record(
        self,
        record: NtsRecord,
    ) -> ControlFlow<Result<Vec<(u16, u16)>, KeyExchangeError>, Self> {
        use ControlFlow::{Break, Continue};
        use NtsRecord::{EndOfMessage, Error, SupportedAlgorithmList, Warning};

        let mut state = self;

        match record {
            EndOfMessage => Break(Ok(state.supported_algorithms)),
            Error { errorcode } => Break(Err(KeyExchangeError::from_error_code(errorcode))),
            Warning { warningcode } => {
                tracing::warn!(warningcode, "Received key exchange warning code");

                Continue(state)
            }
            #[cfg(feature = "nts-pool")]
            SupportedAlgorithmList {
                supported_algorithms,
            } => {
                state.supported_algorithms = supported_algorithms;

                Continue(state)
            }

            _ => Continue(state),
        }
    }
}

/// Pool KE decoding records from the client
#[derive(Debug, Default)]
pub struct ClientToPoolDecoder {
    decoder: NtsRecordDecoder,
    /// AEAD algorithm that the client is able to use and that we support
    /// it may be that the server and client supported algorithms have no
    /// intersection!
    algorithm: AeadAlgorithm,
    /// Protocol (NTP version) that is supported by both client and server
    protocol: ProtocolId,

    records: Vec<NtsRecord>,
    denied_servers: Vec<String>,

    #[cfg(feature = "ntpv5")]
    allow_v5: bool,
}

#[derive(Debug)]
pub struct ClientToPoolData {
    pub algorithm: AeadAlgorithm,
    pub protocol: ProtocolId,
    pub records: Vec<NtsRecord>,
    pub denied_servers: Vec<String>,
}

impl ClientToPoolData {
    /// # Errors
    ///
    /// Returns `KeyExchangeError` if extracting the `NtsKeys` fails.
    pub fn extract_nts_keys<ConnectionData>(
        &self,
        stream: &rustls::ConnectionCommon<ConnectionData>,
    ) -> Result<NtsKeys, KeyExchangeError> {
        self.algorithm
            .extract_nts_keys(self.protocol, stream)
            .map_err(KeyExchangeError::Tls)
    }
}

impl ClientToPoolDecoder {
    #[must_use] pub fn step_with_slice(
        mut self,
        bytes: &[u8],
    ) -> ControlFlow<Result<ClientToPoolData, KeyExchangeError>, Self> {
        self.decoder.extend(bytes.iter().copied());

        loop {
            match self.decoder.step() {
                Err(e) => return ControlFlow::Break(Err(e.into())),
                Ok(Some(record)) => self = self.step_with_record(record)?,
                Ok(None) => return ControlFlow::Continue(self),
            }
        }
    }

    #[inline(always)]
    fn step_with_record(
        self,
        record: NtsRecord,
    ) -> ControlFlow<Result<ClientToPoolData, KeyExchangeError>, Self> {
        use self::AeadAlgorithm as Algorithm;
        use ControlFlow::{Break, Continue};
        use KeyExchangeError::{NoValidAlgorithm, NoValidProtocol};
        use NtsRecord::{AeadAlgorithm, DraftId, EndOfMessage, Error, NextProtocol, NtpServerDeny, Warning};

        let mut state = self;

        match record {
            EndOfMessage => {
                // NOTE EndOfMessage not pushed onto the vector

                let result = ClientToPoolData {
                    algorithm: state.algorithm,
                    protocol: state.protocol,
                    records: state.records,
                    denied_servers: state.denied_servers,
                };

                Break(Ok(result))
            }
            Error { errorcode } => {
                //
                Break(Err(KeyExchangeError::from_error_code(errorcode)))
            }
            Warning { warningcode } => {
                tracing::debug!(warningcode, "Received key exchange warning code");

                state.records.push(record);
                Continue(state)
            }
            #[cfg(feature = "ntpv5")]
            DraftId { data } => {
                if data == crate::packet::v5::DRAFT_VERSION.as_bytes() {
                    state.allow_v5 = true;
                }
                Continue(state)
            }
            NextProtocol { protocol_ids } => {
                #[cfg(feature = "ntpv5")]
                let selected = if state.allow_v5 {
                    protocol_ids
                        .iter()
                        .copied()
                        .find_map(ProtocolId::try_deserialize_v5)
                } else {
                    protocol_ids
                        .iter()
                        .copied()
                        .find_map(ProtocolId::try_deserialize)
                };

                #[cfg(not(feature = "ntpv5"))]
                let selected = protocol_ids
                    .iter()
                    .copied()
                    .find_map(ProtocolId::try_deserialize);

                match selected {
                    None => Break(Err(NoValidProtocol)),
                    Some(protocol) => {
                        state.protocol = protocol;
                        Continue(state)
                    }
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                let selected = algorithm_ids
                    .iter()
                    .copied()
                    .find_map(Algorithm::try_deserialize);

                match selected {
                    None => Break(Err(NoValidAlgorithm)),
                    Some(algorithm) => {
                        state.algorithm = algorithm;
                        Continue(state)
                    }
                }
            }

            #[cfg(feature = "nts-pool")]
            NtpServerDeny { denied } => {
                state.denied_servers.push(denied);
                Continue(state)
            }

            other => {
                // just forward other records blindly
                state.records.push(other);
                Continue(state)
            }
        }
    }
}

/// Pool KE decoding records from the NTS KE
#[derive(Debug, Default)]
pub struct PoolToServerDecoder {
    decoder: NtsRecordDecoder,
    /// AEAD algorithm that the client is able to use and that we support
    /// it may be that the server and client supported algorithms have no
    /// intersection!
    algorithm: AeadAlgorithm,
    /// Protocol (NTP version) that is supported by both client and server
    protocol: ProtocolId,

    records: Vec<NtsRecord>,

    #[cfg(feature = "ntpv5")]
    allow_v5: bool,
}

#[derive(Debug)]
pub struct PoolToServerData {
    pub algorithm: AeadAlgorithm,
    pub protocol: ProtocolId,
    pub records: Vec<NtsRecord>,
}

impl PoolToServerDecoder {
    #[must_use] pub fn step_with_slice(
        mut self,
        bytes: &[u8],
    ) -> ControlFlow<Result<PoolToServerData, KeyExchangeError>, Self> {
        self.decoder.extend(bytes.iter().copied());

        loop {
            match self.decoder.step() {
                Err(e) => return ControlFlow::Break(Err(e.into())),
                Ok(Some(record)) => self = self.step_with_record(record)?,
                Ok(None) => return ControlFlow::Continue(self),
            }
        }
    }

    #[inline(always)]
    fn step_with_record(
        self,
        record: NtsRecord,
    ) -> ControlFlow<Result<PoolToServerData, KeyExchangeError>, Self> {
        use self::AeadAlgorithm as Algorithm;
        use ControlFlow::{Break, Continue};
        use KeyExchangeError::{NoValidAlgorithm, NoValidProtocol};
        use NtsRecord::{AeadAlgorithm, DraftId, EndOfMessage, Error, NextProtocol, Warning};

        let mut state = self;

        match &record {
            EndOfMessage => {
                state.records.push(EndOfMessage);

                let result = PoolToServerData {
                    algorithm: state.algorithm,
                    protocol: state.protocol,
                    records: state.records,
                };

                Break(Ok(result))
            }
            Error { errorcode } => {
                //
                Break(Err(KeyExchangeError::from_error_code(*errorcode)))
            }
            Warning { warningcode } => {
                tracing::debug!(warningcode, "Received key exchange warning code");

                state.records.push(record);
                Continue(state)
            }
            #[cfg(feature = "ntpv5")]
            DraftId { data } => {
                if data == crate::packet::v5::DRAFT_VERSION.as_bytes() {
                    state.allow_v5 = true;
                }
                Continue(state)
            }
            NextProtocol { protocol_ids } => {
                #[cfg(feature = "ntpv5")]
                let selected = if state.allow_v5 {
                    protocol_ids
                        .iter()
                        .copied()
                        .find_map(ProtocolId::try_deserialize_v5)
                } else {
                    protocol_ids
                        .iter()
                        .copied()
                        .find_map(ProtocolId::try_deserialize)
                };

                #[cfg(not(feature = "ntpv5"))]
                let selected = protocol_ids
                    .iter()
                    .copied()
                    .find_map(ProtocolId::try_deserialize);

                state.records.push(record);

                match selected {
                    None => Break(Err(NoValidProtocol)),
                    Some(protocol) => {
                        state.protocol = protocol;
                        Continue(state)
                    }
                }
            }
            AeadAlgorithm { algorithm_ids, .. } => {
                let selected = algorithm_ids
                    .iter()
                    .copied()
                    .find_map(Algorithm::try_deserialize);

                state.records.push(record);

                match selected {
                    None => Break(Err(NoValidAlgorithm)),
                    Some(algorithm) => {
                        state.algorithm = algorithm;
                        Continue(state)
                    }
                }
            }

            _other => {
                // just forward other records blindly
                state.records.push(record);
                Continue(state)
            }
        }
    }
}
