//! The client side of ECH (RFC 9849 §6).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::DnsName;

use super::codec::{
    EchClientHello, EchOuter, find_extension, raw_extensions, server_hello_extensions_offset,
};
use super::{
    ACCEPT_LABEL, EchConfig, EchGreaseConfig, EchStatus, HRR_ACCEPT_LABEL, accept_confirmation,
    hpke_info,
};
use crate::crypto::SecureRandom;
use crate::crypto::hpke::{HpkeSealer, HpkeSymmetricCipherSuite};
use crate::ct::constant_time_eq;
use crate::error::Error;
use crate::hash_hs::HandshakeHashBuffer;
use crate::msgs::base::{PayloadU8, PayloadU16};
use crate::msgs::codec::{Codec, encode_vec_u8, encode_vec_u16};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, PresharedKeyBinder, PresharedKeyIdentity,
    PresharedKeyOffer, Random, ServerNamePayload, SessionId,
};
use crate::tls13::Tls13CipherSuite;

const ECH: u16 = 0xfe0d;
const OUTER_EXTENSIONS: u16 = 0xfd00;
const PRE_SHARED_KEY: u16 = 41;

/// A real ECH offer awaiting the server's answer.
pub(crate) struct EchOffer {
    pub(crate) config: EchConfig,
    sealer: Box<dyn HpkeSealer>,
    enc: Vec<u8>,
    /// The outer ClientHello's own random (§6.1: never the inner one's).
    pub(crate) outer_random: Random,
    /// The transcript as the server sees it if it rejects ECH.
    pub(crate) outer_transcript: HandshakeHashBuffer,
    /// The extensions of the last outer ClientHello.
    pub(crate) outer_sent_extensions: Vec<ExtensionType>,
    /// The first outer ClientHello's ECH extension, which a second
    /// ClientHello repeats when the HelloRetryRequest rejected ECH.
    pub(crate) first_outer_ext: Option<EchClientHello>,
    /// The HelloRetryRequest confirmed acceptance, so the ServerHello must
    /// too (§6.1.5).
    pub(crate) accepted_at_retry: bool,
}

/// The client's ECH state while the hello is being negotiated.
pub(crate) enum ClientEch {
    /// GREASE configured; the extension is built for the first ClientHello.
    GreasePending(EchGreaseConfig),
    /// GREASE sent; a second ClientHello repeats the extension (§6.2).
    Grease(EchClientHello),
    /// A real offer: the ClientHello built is the inner one.
    Offer(Box<EchOffer>),
    /// The HelloRetryRequest rejected ECH: the second ClientHello follows
    /// the outer one, repeating its ECH extension.
    RejectedAtRetry {
        outer_ext: Option<EchClientHello>,
        public_name: DnsName<'static>,
    },
}

impl ClientEch {
    /// Starts an offer with `config`: sets up the HPKE context.
    pub(crate) fn offer(
        config: &EchConfig,
        rng: &dyn SecureRandom,
        client_auth_enabled: bool,
    ) -> Result<Self, Error> {
        let info = hpke_info(&config.encoded);
        let public_key =
            crate::crypto::hpke::HpkePublicKey(config.contents.key_config.public_key.0.clone());
        let (enc, sealer) = config.hpke.setup_sealer(&info, &public_key)?;
        let mut outer_transcript = HandshakeHashBuffer::new();
        if client_auth_enabled {
            outer_transcript.set_client_auth_enabled();
        }
        Ok(Self::Offer(Box::new(EchOffer {
            config: config.clone(),
            sealer,
            enc: enc.0,
            outer_random: Random::new(rng)?,
            outer_transcript,
            outer_sent_extensions: Vec::new(),
            first_outer_ext: None,
            accepted_at_retry: false,
        })))
    }

    /// The status to report before the server answers.
    pub(crate) fn initial_status(&self) -> EchStatus {
        match self {
            Self::GreasePending(_) | Self::Grease(_) => EchStatus::Grease,
            Self::Offer(_) => EchStatus::Offered,
            Self::RejectedAtRetry { .. } => EchStatus::Rejected,
        }
    }

    /// Whether the ClientHello must offer TLS 1.3 only (§6.1): true for a
    /// real offer and for what follows its rejection.
    pub(crate) fn restricts_to_tls13(&self) -> bool {
        matches!(self, Self::Offer(_) | Self::RejectedAtRetry { .. })
    }

    /// Adds this state's extensions to a ClientHello about to be built.
    /// `other_len` is the length of everything but the extensions, for
    /// sizing a GREASE payload.
    pub(crate) fn prepare(
        &mut self,
        exts: &mut ClientExtensions,
        other_len: usize,
        rng: &dyn SecureRandom,
    ) -> Result<(), Error> {
        match self {
            Self::GreasePending(grease) => {
                let ext = grease_extension(grease, exts, other_len, rng)?;
                exts.encrypted_client_hello = Some(ext.clone());
                *self = Self::Grease(ext);
            }
            Self::Grease(ext) => exts.encrypted_client_hello = Some(ext.clone()),
            Self::Offer(_) => exts.encrypted_client_hello = Some(EchClientHello::Inner),
            Self::RejectedAtRetry {
                outer_ext,
                public_name,
            } => {
                exts.encrypted_client_hello = outer_ext.clone();
                exts.server_name = Some(ServerNamePayload::SingleDnsName(public_name.clone()));
                exts.protocols = None;
            }
        }
        Ok(())
    }
}

impl EchOffer {
    /// Builds the outer ClientHello for `inner` (complete, PSK binder
    /// included) and seals `inner` into it (§6.1.1). After a
    /// HelloRetryRequest, `enc` is empty and the HPKE context continues.
    pub(crate) fn seal_outer(
        &mut self,
        inner: &ClientHelloPayload,
        retry: bool,
        rng: &dyn SecureRandom,
    ) -> Result<ClientHelloPayload, Error> {
        let mut outer = inner.clone();
        outer.random = self.outer_random;
        let exts = &mut outer.extensions;
        exts.server_name = Some(ServerNamePayload::SingleDnsName(
            self.config.public_name.clone(),
        ));
        // Sensitive, and not needed to authenticate a rejection.
        exts.protocols = None;
        exts.early_data = None;
        exts.encrypted_client_hello = None;
        // §6.1.2: a PSK in the inner hello is mirrored by a GREASE one.
        exts.preshared_key = match &inner.extensions.preshared_key {
            Some(psk) => Some(grease_psk(psk, rng)?),
            None => None,
        };

        let encoded_inner = encode_inner(
            inner,
            &outer.extensions,
            self.config.contents.maximum_name_length,
        );
        let tag_len = self
            .config
            .cipher_suite
            .aead_id
            .tag_len()
            .ok_or_else(|| Error::general("ECH AEAD has no known tag length"))?;
        let payload_len = encoded_inner.len() + tag_len;
        let enc = if retry { Vec::new() } else { self.enc.clone() };
        let mut ech = EchOuter {
            cipher_suite: self.config.cipher_suite,
            config_id: self.config.contents.key_config.config_id,
            enc: PayloadU16::new(enc),
            payload: PayloadU16::new(vec![0; payload_len]),
        };
        outer.extensions.encrypted_client_hello = Some(EchClientHello::Outer(ech.clone()));
        let aad = outer.get_encoding();
        let payload = self.sealer.seal(&aad, &encoded_inner)?;
        if payload.len() != payload_len {
            return Err(Error::general("ECH ciphertext has an unexpected length"));
        }
        ech.payload = PayloadU16::new(payload);
        let ext = EchClientHello::Outer(ech);
        if !retry {
            self.first_outer_ext = Some(ext.clone());
        }
        outer.extensions.encrypted_client_hello = Some(ext);
        self.outer_sent_extensions = outer.extensions.present_types();
        Ok(outer)
    }
}

/// `EncodedClientHelloInner` (§5.1): `inner` with an empty session ID, the
/// longest run of extensions identical in `outer` replaced by
/// `ech_outer_extensions`, and padding (§6.1.3).
pub(super) fn encode_inner(
    inner: &ClientHelloPayload,
    outer: &ClientExtensions,
    maximum_name_length: u8,
) -> Vec<u8> {
    let inner_block = inner.extensions.get_encoding();
    let outer_block = outer.get_encoding();
    let inner_exts = raw_extensions(&inner_block).unwrap_or_default();
    let outer_exts = raw_extensions(&outer_block).unwrap_or_default();

    let compressible: Vec<bool> = inner_exts
        .iter()
        .map(|e| {
            e.typ != ECH
                && e.typ != PRE_SHARED_KEY
                && outer_exts
                    .iter()
                    .any(|o| inner_block[e.whole.clone()] == outer_block[o.whole.clone()])
        })
        .collect();
    // The longest contiguous run, by bytes saved; OuterExtensions holds at
    // most 127 types.
    let mut best: Option<(usize, usize)> = None;
    let mut best_bytes = 0;
    let mut i = 0;
    while i < inner_exts.len() {
        if !compressible[i] {
            i += 1;
            continue;
        }
        let mut j = i;
        let mut bytes = 0;
        while j < inner_exts.len() && compressible[j] && j - i < 127 {
            bytes += inner_exts[j].whole.len();
            j += 1;
        }
        if bytes > best_bytes && bytes > 4 + 1 + 2 * (j - i) {
            best = Some((i, j));
            best_bytes = bytes;
        }
        i = j;
    }

    let mut out = Vec::new();
    inner.client_version.encode(&mut out);
    inner.random.encode(&mut out);
    SessionId::empty().encode(&mut out);
    encode_vec_u16(&mut out, &inner.cipher_suites);
    encode_vec_u8(&mut out, &inner.compression_methods);
    let mut block = Vec::new();
    let mut k = 0;
    while k < inner_exts.len() {
        if let Some((start, end)) = best
            && k == start
        {
            let types: Vec<u8> = inner_exts[start..end]
                .iter()
                .flat_map(|e| e.typ.to_be_bytes())
                .collect();
            block.extend_from_slice(&OUTER_EXTENSIONS.to_be_bytes());
            block.extend_from_slice(&((types.len() + 1) as u16).to_be_bytes());
            block.push(types.len() as u8);
            block.extend_from_slice(&types);
            k = end;
            continue;
        }
        block.extend_from_slice(&inner_block[inner_exts[k].whole.clone()]);
        k += 1;
    }
    out.extend_from_slice(&(block.len() as u16).to_be_bytes());
    out.extend_from_slice(&block);

    let name_len = inner.sni().map(|n| n.as_ref().len());
    let padding = padding_len(out.len(), name_len, maximum_name_length);
    out.resize(out.len() + padding, 0);
    out
}

/// The recommended padding (§6.1.3): up to `maximum_name_length` for the
/// server name, then up to a multiple of 32.
fn padding_len(len: usize, name_len: Option<usize>, maximum_name_length: u8) -> usize {
    let max = usize::from(maximum_name_length);
    let name_padding = match name_len {
        Some(d) => max.saturating_sub(d),
        None => max + 9,
    };
    let total = len + name_padding;
    name_padding + (31 - ((total - 1) % 32))
}

/// A GREASE `pre_shared_key` shaped like `psk` (§6.1.2).
fn grease_psk(psk: &PresharedKeyOffer, rng: &dyn SecureRandom) -> Result<PresharedKeyOffer, Error> {
    let mut identities = Vec::with_capacity(psk.identities.len());
    for id in &psk.identities {
        let mut identity = vec![0u8; id.identity.0.len()];
        rng.fill(&mut identity)?;
        let mut age = [0u8; 4];
        rng.fill(&mut age)?;
        identities.push(PresharedKeyIdentity::new(identity, u32::from_be_bytes(age)));
    }
    let mut binders = Vec::with_capacity(psk.binders.len());
    for binder in &psk.binders {
        let mut bytes = vec![0u8; binder.as_ref().len()];
        rng.fill(&mut bytes)?;
        binders.push(PresharedKeyBinder(PayloadU8::new(bytes)));
    }
    Ok(PresharedKeyOffer {
        identities,
        binders,
    })
}

/// A GREASE ECH extension (§6.2.1): a random `config_id`, a real `enc` and
/// a random payload as long as a padded inner ClientHello would make it.
fn grease_extension(
    grease: &EchGreaseConfig,
    exts: &ClientExtensions,
    other_len: usize,
    rng: &dyn SecureRandom,
) -> Result<EchClientHello, Error> {
    let suite = grease.hpke.suite();
    let (enc, _) = grease.hpke.setup_sealer(&[], &grease.placeholder_key)?;
    let mut config_id = [0u8; 1];
    rng.fill(&mut config_id)?;
    let name_len = match &exts.server_name {
        Some(ServerNamePayload::SingleDnsName(name)) => Some(name.as_ref().len()),
        _ => None,
    };
    // The inner hello would carry an `inner` ECH extension (4 + 1 bytes)
    // and an empty session ID.
    let len = other_len + exts.get_encoding().len() + 5;
    let len = len + padding_len(len, name_len, 0);
    let mut payload = vec![0u8; len + suite.sym.aead_id.tag_len().unwrap_or(16)];
    rng.fill(&mut payload)?;
    Ok(EchClientHello::Outer(EchOuter {
        cipher_suite: HpkeSymmetricCipherSuite {
            kdf_id: suite.sym.kdf_id,
            aead_id: suite.sym.aead_id,
        },
        config_id: config_id[0],
        enc: PayloadU16::new(enc.0),
        payload: PayloadU16::new(payload),
    }))
}

/// Whether `server_hello` (the whole handshake message) confirms ECH
/// (§6.1.4): its random ends with `accept_confirmation` over the inner
/// transcript and the ServerHello with those bytes zeroed.
pub(crate) fn server_hello_accepts(
    inner_transcript: &HandshakeHashBuffer,
    suite: &'static Tls13CipherSuite,
    inner_random: &Random,
    server_hello: &[u8],
) -> bool {
    // Handshake header (4), legacy_version (2), random (32).
    const CONF: core::ops::Range<usize> = 4 + 2 + 24..4 + 2 + 32;
    let Some(received) = server_hello.get(CONF) else {
        return false;
    };
    let mut zeroed = server_hello.to_vec();
    zeroed[CONF].fill(0);
    let hash = inner_transcript.hash_given(suite.common.hash_provider, &zeroed);
    let expected = accept_confirmation(
        suite.hkdf_provider,
        &inner_random.0,
        ACCEPT_LABEL,
        hash.as_ref(),
    );
    constant_time_eq(&expected, received)
}

/// Whether a HelloRetryRequest (the whole handshake message) confirms ECH
/// (§6.1.4), given the inner transcript after the first ClientHello was
/// replaced by its hash.
pub(crate) fn retry_request_accepts(
    inner_transcript: &HandshakeHashBuffer,
    suite: &'static Tls13CipherSuite,
    inner_random: &Random,
    hrr: &[u8],
) -> bool {
    let Some(body) = hrr.get(4..) else {
        return false;
    };
    let Some(range) = find_extension(body, server_hello_extensions_offset, ECH) else {
        return false;
    };
    if range.len() != 8 {
        return false;
    }
    let range = 4 + range.start..4 + range.end;
    let mut zeroed = hrr.to_vec();
    zeroed[range.clone()].fill(0);
    let hash = inner_transcript.hash_given(suite.common.hash_provider, &zeroed);
    let expected = accept_confirmation(
        suite.hkdf_provider,
        &inner_random.0,
        HRR_ACCEPT_LABEL,
        hash.as_ref(),
    );
    constant_time_eq(&expected, &hrr[range])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_rounds_to_32() {
        // No name padding: just round up.
        assert_eq!(padding_len(1, Some(5), 0), 31);
        assert_eq!(padding_len(32, Some(5), 0), 0);
        assert_eq!(padding_len(33, Some(5), 0), 31);
        // A short name pads to the maximum name length first.
        assert_eq!(padding_len(100, Some(10), 20), 10 + 18);
        // No name: L + 9.
        assert_eq!(padding_len(100, None, 20), 29 + 31);
        for len in 1..200 {
            for name in [None, Some(3), Some(40)] {
                assert_eq!((len + padding_len(len, name, 32)) % 32, 0);
            }
        }
    }
}
