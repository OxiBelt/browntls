//! Command-line configuration for binary and RFC 9934 ECH inputs.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use browntls::crypto::hpke::{Hpke, HpkeKem, HpkePrivateKey};
use browntls::crypto::native::hpke::{ALL_SUPPORTED_SUITES, DH_KEM_X25519_HKDF_SHA256_AES_128};
use browntls::ech::pem::{EchPem, NATIVE_PKCS8_CODEC};
use browntls::ech::{EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey};

use super::output::{Value, emit};
use super::{Options, Result, read_file, required};

const X25519: HpkeKem = HpkeKem::DHKEM_X25519_HKDF_SHA256;

pub(super) fn parse_kem(value: &str) -> Result<HpkeKem> {
    Ok(match value {
        "x25519" => X25519,
        "x448" => HpkeKem::DHKEM_X448_HKDF_SHA512,
        "p256" => HpkeKem::DHKEM_P256_HKDF_SHA256,
        "p384" => HpkeKem::DHKEM_P384_HKDF_SHA384,
        "p521" => HpkeKem::DHKEM_P521_HKDF_SHA512,
        _ => return Err("unknown ECH KEM (expected x25519, x448, p256, p384 or p521)".into()),
    })
}

impl Options {
    pub(super) fn validate_ech_options(&self, command: &str) -> Result<()> {
        let pem = !self.ech_pems.is_empty();
        let retry = !self.ech_retry_pems.is_empty();
        if self.ech_kem.is_some() && !self.ech_keygen_pem {
            return Err("--ech-kem requires ech-keygen --ech-pem".into());
        }
        match command {
            "client" if retry || self.ech_pems.len() > 1 => {
                Err("the client accepts only one public --ech-pem and no retry files".into())
            }
            "client" if pem && (self.ech_config_list.is_some() || self.ech_grease) => {
                Err("--ech-pem cannot be combined with --ech-config-list or --ech-grease".into())
            }
            "server" | "client-facing" if pem != retry => {
                Err("--ech-pem and --ech-retry-pem go together".into())
            }
            "server" | "client-facing"
                if pem
                    && (self.ech_backend
                        || self.ech_config.is_some()
                        || self.ech_key.is_some()) =>
            {
                Err("PEM bundles require shared mode or a client-facing server".into())
            }
            "dtls-server" | "dtls-client" | "ech-keygen" if pem || retry => {
                Err("ECH PEM input is available for TLS clients and servers".into())
            }
            _ => Ok(()),
        }
    }

    /// Loads the configured keys and the ordered selection for retry.
    pub(super) fn ech_server(&self) -> Result<Option<Arc<EchServerConfig>>> {
        let mut ech = if self.ech_pems.is_empty() {
            let (config, key) = match (&self.ech_config, &self.ech_key) {
                (Some(config), Some(key)) => (read_file(config)?, read_file(key)?),
                (None, None) => return Ok(None),
                _ => return Err("--ech-config and --ech-key go together".into()),
            };
            let key =
                EchServerKey::new(&config, HpkePrivateKey::from(key), &suites_for_kem(X25519))
                    .map_err(|e| format!("ECH key: {e}"))?;
            EchServerConfig::new(vec![key]).map_err(|e| e.to_string())?
        } else {
            let load = |paths: &[String]| {
                paths
                    .iter()
                    .map(|file| {
                        EchPem::from_pem_file(file, Some(&NATIVE_PKCS8_CODEC))
                            .map_err(|e| format!("ECH PEM {file}: {e}"))
                    })
                    .collect::<Result<Vec<_>>>()
            };
            let keys = load(&self.ech_pems)?;
            let retry = load(&self.ech_retry_pems)?;
            EchServerConfig::from_pems(&keys, &retry, ALL_SUPPORTED_SUITES)
                .map_err(|e| e.to_string())?
        };
        if self.ech_trial_decryption {
            ech = ech.with_trial_decryption();
        }
        if self.ech_public_name_check {
            ech = ech.with_public_name_check();
        }
        Ok(Some(Arc::new(ech)))
    }

    /// The client's ECH mode. A retry uses the authenticated list from
    /// the prior connection instead of its original configuration file.
    pub(super) fn ech_client(&self, list: Option<&[u8]>) -> Result<Option<EchMode>> {
        if self.ech_grease {
            let grease = EchGreaseConfig::generate(DH_KEM_X25519_HKDF_SHA256_AES_128)
                .map_err(|e| e.to_string())?;
            return Ok(Some(EchMode::Grease(grease)));
        }
        let mut config = match (list, &self.ech_config_list, self.ech_pems.first()) {
            (Some(list), _, _) => {
                EchConfig::new(list, ALL_SUPPORTED_SUITES).map_err(|e| format!("ECH: {e}"))?
            }
            (None, Some(path), _) => EchConfig::new(&read_file(path)?, ALL_SUPPORTED_SUITES)
                .map_err(|e| format!("ECH: {e}"))?,
            (None, None, Some(path)) => {
                let pem = EchPem::from_pem_file(path, None).map_err(|e| format!("ECH PEM: {e}"))?;
                EchConfig::from_pem(&pem, ALL_SUPPORTED_SUITES).map_err(|e| format!("ECH: {e}"))?
            }
            (None, None, None) => return Ok(None),
        };
        if self.ech_random_config_id {
            config = config.with_random_config_id();
        }
        Ok(Some(EchMode::Enable(config)))
    }
}

fn suites_for_kem(kem: HpkeKem) -> Vec<&'static dyn Hpke> {
    ALL_SUPPORTED_SUITES
        .iter()
        .copied()
        .filter(|suite| suite.suite().kem == kem)
        .collect()
}

pub(super) fn keygen(o: &Options) -> Result<()> {
    let out = PathBuf::from(required(o.out.as_ref(), "--out")?);
    let public_name = required(o.public_name.as_ref(), "--public-name")?;
    let suites = suites_for_kem(o.ech_kem.unwrap_or(X25519));
    let key =
        EchServerKey::generate(o.config_id, public_name, 0, &suites).map_err(|e| e.to_string())?;
    let list = EchServerConfig::new(vec![key.clone()]).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    if o.ech_keygen_pem {
        let pem = EchPem::from_server_key(&key, list.ech_config_list(), &NATIVE_PKCS8_CODEC)
            .map_err(|e| e.to_string())?;
        let private = pem
            .to_private_pem(&NATIVE_PKCS8_CODEC)
            .map_err(|e| e.to_string())?;
        let public = pem.to_public_pem();
        let private_path = out.join("ech.pem");
        write_new(&private_path, private.as_bytes(), true)?;
        if let Err(error) = write_new(&out.join("ech-public.pem"), &public, false) {
            let _ = std::fs::remove_file(private_path);
            return Err(error);
        }
    } else {
        for (name, bytes) in [
            ("ech-config", key.ech_config()),
            ("ech-config-list", list.ech_config_list()),
            ("ech-key", key.private_key().secret_bytes()),
        ] {
            let path = out.join(name);
            std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    emit(&[
        ("event", "ech-key".into()),
        ("config_id", Value::Num(usize::from(o.config_id))),
        ("public_name", public_name.into()),
    ]);
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        if private {
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("{}: {error}", path.display()));
    }
    Ok(())
}
