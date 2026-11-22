//! RFC 9934 ECH configuration files.
//!
//! A file carries one ordered ECHConfigList and, optionally, one PKCS #8
//! private key. Use the public-only representation for clients or DNS
//! publication. The native key codec is available with the `native` feature.
//! Callers using another implementation can supply their own key codec.

use alloc::vec::Vec;
use core::fmt;

use super::{EchServerKey, config};
use crate::crypto::hpke::{HpkeKem, HpkePrivateKey, HpkePublicKey};
use crate::{Error, crypto};

mod framing;
#[cfg(feature = "native")]
mod native;
#[cfg(test)]
mod tests;

#[cfg(feature = "native")]
pub use native::{NATIVE_PKCS8_CODEC, NativeEchPkcs8Codec};

/// An error while decoding, encoding or using an ECH PEM file.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum EchPemError {
    /// A block had an unexpected label, order, delimiter or Base64 body.
    InvalidPem,
    /// A file or private key exceeded the decoder's size limit.
    InputTooLarge,
    /// The private key's PKCS #8 encoding or algorithm is unsupported.
    InvalidPrivateKey,
    /// The file contained a private key but no key codec was supplied.
    MissingKeyCodec,
    /// A key operation required a private key, but the file was public-only.
    MissingPrivateKey,
    /// The private key did not correspond to any understood config.
    KeyMismatch,
    /// The server could not install a matching config with the given suites.
    NoUsableDecryptionKey,
    /// The server had too many entries eligible for decryption.
    TooManyDecryptionKeys,
    /// The ordered retry selection was empty, malformed or too large.
    InvalidRetryList,
    /// The ECH configuration or TLS connection could not be constructed.
    Tls(Error),
    /// Reading or writing the file failed.
    #[cfg(feature = "std")]
    Io(std::io::ErrorKind),
}

impl fmt::Display for EchPemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPem => "invalid ECH PEM file",
            Self::InputTooLarge => "ECH PEM input exceeds its size limit",
            Self::InvalidPrivateKey => "invalid or unsupported ECH PKCS #8 key",
            Self::MissingKeyCodec => "an ECH PKCS #8 key codec is required",
            Self::MissingPrivateKey => "an ECH private key is required",
            Self::KeyMismatch => "ECH private key does not match the ECHConfigList",
            Self::NoUsableDecryptionKey => "no usable ECH decryption key",
            Self::TooManyDecryptionKeys => "too many ECH decryption keys",
            Self::InvalidRetryList => "invalid ECH retry configuration list",
            Self::Tls(error) => return write!(f, "{error}"),
            #[cfg(feature = "std")]
            Self::Io(kind) => return write!(f, "ECH PEM I/O failed: {kind}"),
        })
    }
}

impl core::error::Error for EchPemError {}

/// An owned private encoding which is wiped on drop.
///
/// The caller is responsible for borrowed inputs and for any copies it makes
/// of these bytes. Debug output is redacted.
pub struct EchSecretBytes(Vec<u8>);

impl EchSecretBytes {
    /// Borrows the private encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for EchSecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Drop for EchSecretBytes {
    fn drop(&mut self) {
        crypto::zeroize_vec(&mut self.0);
    }
}

impl fmt::Debug for EchSecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EchSecretBytes(<redacted>)")
    }
}

/// The private-key format adapter for an ECH implementation.
///
/// Return the private representation expected by the selected HPKE suites
/// and the independently derived, HPKE-serialized public key. A codec must
/// protect its own private buffers and avoid exposing secrets in errors.
pub trait EchPkcs8Codec {
    /// Decodes an unencrypted PKCS #8 key and derives its public key.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported algorithms or invalid keys.
    fn decode_pkcs8(
        &self,
        input: &[u8],
    ) -> Result<(HpkeKem, HpkePrivateKey, HpkePublicKey), EchPemError>;

    /// Encodes the private key as DER and derives its public key.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported algorithms or invalid keys.
    fn encode_pkcs8(
        &self,
        kem: HpkeKem,
        private: &HpkePrivateKey,
    ) -> Result<(EchSecretBytes, HpkePublicKey), EchPemError>;
}

/// An authenticated key-to-config association from an RFC 9934 file.
///
/// The key match says nothing about which server or name a caller should
/// trust. Validate the source of a configuration before using it.
pub struct EchPem {
    list: Vec<u8>,
    private: Option<(HpkeKem, HpkePrivateKey, HpkePublicKey)>,
}

impl fmt::Debug for EchPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchPem")
            .field("config_list_length", &self.list.len())
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

impl EchPem {
    /// Loads a PEM file from bytes, stopping at the first `ECHCONFIG` end.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid framing, excessive input, malformed
    /// configurations, an unavailable key codec or a nonmatching key.
    pub fn from_pem_slice(
        input: &[u8],
        codec: Option<&dyn EchPkcs8Codec>,
    ) -> Result<Self, EchPemError> {
        let mut bytes = input.iter().copied();
        Self::read(|_| Ok(bytes.next()), codec)
    }

    /// Loads a PEM file from a reader. The final read may include trailing
    /// bytes after the `ECHCONFIG` block, which are ignored.
    ///
    /// # Errors
    ///
    /// Returns I/O errors and the same format errors as
    /// [`Self::from_pem_slice`].
    #[cfg(feature = "std")]
    pub fn from_pem_reader(
        mut reader: impl std::io::Read,
        codec: Option<&dyn EchPkcs8Codec>,
    ) -> Result<Self, EchPemError> {
        let mut chunk = EchSecretBytes(alloc::vec![0; 4096]);
        let (mut offset, mut end) = (0, 0);
        Self::read(
            |remaining| {
                if offset == end {
                    offset = 0;
                    end = loop {
                        let count = remaining.min(chunk.0.len());
                        match reader.read(&mut chunk.0[..count]) {
                            Ok(count) => break count,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(EchPemError::Io(e.kind())),
                        }
                    };
                    if end == 0 {
                        return Ok(None);
                    }
                }
                let byte = chunk.0[offset];
                offset += 1;
                Ok(Some(byte))
            },
            codec,
        )
    }

    /// Loads an ECH file at a local path.
    ///
    /// # Errors
    ///
    /// Returns I/O errors and the same format errors as
    /// [`Self::from_pem_slice`].
    #[cfg(feature = "std")]
    pub fn from_pem_file(
        path: impl AsRef<std::path::Path>,
        codec: Option<&dyn EchPkcs8Codec>,
    ) -> Result<Self, EchPemError> {
        let file = std::fs::File::open(path).map_err(|e| EchPemError::Io(e.kind()))?;
        Self::from_pem_reader(file, codec)
    }

    fn read(
        next: impl FnMut(usize) -> Result<Option<u8>, EchPemError>,
        codec: Option<&dyn EchPkcs8Codec>,
    ) -> Result<Self, EchPemError> {
        let (prefix, private, public) = framing::read(next)?;
        let list = browntls_pki::pem::base64_decode(&prefix.0[public])
            .map_err(|_| EchPemError::InvalidPem)?;
        let mut pem = Self::from_config_list_vec(list)?;
        if let Some(private) = private {
            let codec = codec.ok_or(EchPemError::MissingKeyCodec)?;
            let der = framing::decode_private(&prefix.0[private])?;
            let (kem, key, public) = codec.decode_pkcs8(der.as_bytes())?;
            pem.attach(kem, key, public)?;
        }
        Ok(pem)
    }

    /// Wraps a serialized public ECHConfigList as a public-only PEM file.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed list.
    pub fn from_config_list(list: &[u8]) -> Result<Self, EchPemError> {
        if list.len() > usize::from(u16::MAX) + 2 {
            return Err(EchPemError::InputTooLarge);
        }
        Self::from_config_list_vec(list.to_vec())
    }

    fn from_config_list_vec(list: Vec<u8>) -> Result<Self, EchPemError> {
        config::read_config_list(&list)
            .map_err(Error::from)
            .map_err(EchPemError::Tls)?;
        Ok(Self {
            list,
            private: None,
        })
    }

    /// Combines a server key with an ordered list containing its config.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid list, a codec error or a nonmatching
    /// key.
    pub fn from_server_key(
        key: &EchServerKey,
        list: &[u8],
        codec: &dyn EchPkcs8Codec,
    ) -> Result<Self, EchPemError> {
        let mut pem = Self::from_config_list(list)?;
        let (_, public) = codec.encode_pkcs8(key.kem(), key.private_key())?;
        pem.attach(key.kem(), key.private_key().clone(), public)?;
        Ok(pem)
    }

    fn attach(
        &mut self,
        kem: HpkeKem,
        private: HpkePrivateKey,
        public: HpkePublicKey,
    ) -> Result<(), EchPemError> {
        let entries = config::read_config_list(&self.list)
            .map_err(Error::from)
            .map_err(EchPemError::Tls)?;
        if !entries.iter().any(|entry| {
            entry.contents.as_ref().is_some_and(|contents| {
                contents.key_config.kem_id == kem && contents.key_config.public_key.0 == public.0
            })
        }) {
            return Err(EchPemError::KeyMismatch);
        }
        self.private = Some((kem, private, public));
        Ok(())
    }

    /// The exact serialized ECHConfigList, including its length prefix.
    pub fn ech_config_list(&self) -> &[u8] {
        &self.list
    }

    /// Whether this bundle includes a private key.
    pub fn has_private_key(&self) -> bool {
        self.private.is_some()
    }

    pub(super) fn key(&self) -> Option<(HpkeKem, &HpkePrivateKey, &HpkePublicKey)> {
        self.private
            .as_ref()
            .map(|(kem, key, public)| (*kem, key, public))
    }

    /// Exports only the public configuration as an `ECHCONFIG` PEM block.
    pub fn to_public_pem(&self) -> Vec<u8> {
        let mut out = Vec::new();
        framing::encode(b"ECHCONFIG", &self.list, &mut out);
        out
    }

    /// Exports the private key and configuration as one PEM bundle.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no private key, the codec cannot encode
    /// it, or the codec reports a different public key.
    pub fn to_private_pem(&self, codec: &dyn EchPkcs8Codec) -> Result<EchSecretBytes, EchPemError> {
        let (kem, private, expected) = self.key().ok_or(EchPemError::MissingPrivateKey)?;
        let (der, public) = codec.encode_pkcs8(kem, private)?;
        if public.0 != expected.0 {
            return Err(EchPemError::KeyMismatch);
        }
        if der.0.len() > framing::MAX_PRIVATE_KEY {
            return Err(EchPemError::InputTooLarge);
        }
        let mut out = EchSecretBytes(Vec::with_capacity(
            framing::encoded_capacity(der.0.len()) + framing::encoded_capacity(self.list.len()),
        ));
        framing::encode(b"PRIVATE KEY", der.as_bytes(), &mut out.0);
        framing::encode(b"ECHCONFIG", &self.list, &mut out.0);
        Ok(out)
    }

    /// Writes a public-only PEM file to a writer.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer fails.
    #[cfg(feature = "std")]
    pub fn write_public_pem(&self, mut writer: impl std::io::Write) -> Result<(), EchPemError> {
        writer
            .write_all(&self.to_public_pem())
            .map_err(|e| EchPemError::Io(e.kind()))
    }

    /// Writes a private-key bundle to a writer. The caller must protect the
    /// destination and any additional buffering by the writer.
    ///
    /// # Errors
    ///
    /// Returns I/O errors and the same errors as [`Self::to_private_pem`].
    #[cfg(feature = "std")]
    pub fn write_private_pem(
        &self,
        mut writer: impl std::io::Write,
        codec: &dyn EchPkcs8Codec,
    ) -> Result<(), EchPemError> {
        let pem = self.to_private_pem(codec)?;
        writer
            .write_all(pem.as_bytes())
            .map_err(|e| EchPemError::Io(e.kind()))
    }
}
