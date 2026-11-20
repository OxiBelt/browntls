//! TLS 1.2 key exchange messages (RFC 8422 §5.4, RFC 5246 §7.4.3/§7.4.7).

use alloc::vec::Vec;

use super::KeyExchangeAlgorithm;
use crate::error::InvalidMessage;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{ECCurveType, NamedGroup};
use crate::verify::DigitallySignedStruct;

/// `ECParameters` restricted to named curves (RFC 8422 §5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EcParameters {
    pub(crate) curve_type: ECCurveType,
    pub(crate) named_group: NamedGroup,
}

impl Codec<'_> for EcParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_type.encode(bytes);
        self.named_group.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let curve_type = ECCurveType::read(r)?;
        if curve_type != ECCurveType::NamedCurve {
            return Err(InvalidMessage::UnsupportedCurveType);
        }
        Ok(Self {
            curve_type,
            named_group: NamedGroup::read(r)?,
        })
    }
}

/// The client's ECDH public value (`ClientKeyExchange` body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientEcdhParams {
    pub(crate) public: PayloadU8,
}

impl Codec<'_> for ClientEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let public = PayloadU8::read(r)?;
        if public.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self { public })
    }
}

/// `ServerECDHParams` (RFC 8422 §5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerEcdhParams {
    pub(crate) curve_params: EcParameters,
    pub(crate) public: PayloadU8,
}

impl ServerEcdhParams {
    pub(crate) fn new(group: NamedGroup, pub_key: &[u8]) -> Self {
        Self {
            curve_params: EcParameters {
                curve_type: ECCurveType::NamedCurve,
                named_group: group,
            },
            public: PayloadU8::new(pub_key.to_vec()),
        }
    }
}

impl Codec<'_> for ServerEcdhParams {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.curve_params.encode(bytes);
        self.public.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let curve_params = EcParameters::read(r)?;
        let public = PayloadU8::read(r)?;
        if public.0.is_empty() {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        Ok(Self {
            curve_params,
            public,
        })
    }
}

/// The parameters half of a decoded ServerKeyExchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServerKeyExchangeParams {
    Ecdh(ServerEcdhParams),
}

impl ServerKeyExchangeParams {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Ecdh(p) => p.encode(bytes),
        }
    }
}

/// A decoded ServerKeyExchange: parameters plus the signature over them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerKeyExchange {
    pub(crate) params: ServerKeyExchangeParams,
    pub(crate) dss: DigitallySignedStruct,
}

impl ServerKeyExchange {
    pub(crate) fn encode(&self, bytes: &mut Vec<u8>) {
        self.params.encode(bytes);
        self.dss.encode(bytes);
    }
}

/// A ServerKeyExchange as it arrives: its layout depends on the negotiated key
/// exchange algorithm, so it is kept opaque until the suite is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServerKeyExchangePayload {
    Known(ServerKeyExchange),
    Unknown(Payload<'static>),
}

impl Codec<'_> for ServerKeyExchangePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Known(x) => x.encode(bytes),
            Self::Unknown(x) => x.encode(bytes),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self::Unknown(Payload::read(r).into_owned()))
    }
}

impl ServerKeyExchangePayload {
    /// Decodes the opaque payload now that the key exchange algorithm is known.
    pub(crate) fn unwrap_given_kxa(
        &self,
        kxa: KeyExchangeAlgorithm,
    ) -> Result<ServerKeyExchange, InvalidMessage> {
        match self {
            Self::Known(x) => Ok(x.clone()),
            Self::Unknown(unk) => {
                let mut r = Reader::init(unk.bytes());
                let params = match kxa {
                    KeyExchangeAlgorithm::ECDHE => {
                        ServerKeyExchangeParams::Ecdh(ServerEcdhParams::read(&mut r)?)
                    }
                    other => return Err(InvalidMessage::UnsupportedKeyExchangeAlgorithm(other)),
                };
                let dss = DigitallySignedStruct::read(&mut r)?;
                r.expect_empty("ServerKeyExchange")?;
                Ok(ServerKeyExchange { params, dss })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SignatureScheme;

    #[test]
    fn ecdhe_server_kx_roundtrip() {
        let skx = ServerKeyExchange {
            params: ServerKeyExchangeParams::Ecdh(ServerEcdhParams::new(
                NamedGroup::X25519,
                &[1; 32],
            )),
            dss: DigitallySignedStruct::new(SignatureScheme::ED25519, alloc::vec![2; 64]),
        };
        let mut enc = Vec::new();
        skx.encode(&mut enc);
        let opaque = ServerKeyExchangePayload::read_bytes(&enc).unwrap();
        assert_eq!(
            opaque
                .unwrap_given_kxa(KeyExchangeAlgorithm::ECDHE)
                .unwrap(),
            skx
        );
        assert_eq!(
            opaque.unwrap_given_kxa(KeyExchangeAlgorithm::DHE),
            Err(InvalidMessage::UnsupportedKeyExchangeAlgorithm(
                KeyExchangeAlgorithm::DHE
            ))
        );
        // explicit curve type is refused
        let bad = [1, 0, 0x1d, 1, 1];
        assert_eq!(
            ServerEcdhParams::read_bytes(&bad),
            Err(InvalidMessage::UnsupportedCurveType)
        );
        // empty point refused
        assert_eq!(
            ClientEcdhParams::read_bytes(&[0]),
            Err(InvalidMessage::IllegalEmptyValue)
        );
    }
}
