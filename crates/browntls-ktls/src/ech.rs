//! Prepare userspace TLS connections with ECH for a later kernel handoff.
//!
//! ECH and the handshake run in userspace. To allow a later kernel
//! handoff, set `enable_secret_extraction` on the supplied configuration.

use std::sync::Arc;

use browntls_core::crypto::hpke::Hpke;
use browntls_core::ech::pem::{EchPem, EchPemError};
use browntls_core::ech::{EchConfig, EchMode, EchServerConfig};
use browntls_core::pki_types::ServerName;
use browntls_core::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

/// Creates a userspace client connection with ECH.
///
/// Installs the first usable ECH configuration from `pem` and preserves the
/// other client settings. Returns PEM setup or TLS construction errors.
pub fn prepare_client(
    mut config: ClientConfig,
    server_name: ServerName<'static>,
    pem: &EchPem,
    suites: &[&'static dyn Hpke],
) -> Result<ClientConnection, EchPemError> {
    config.ech_mode = Some(EchMode::Enable(EchConfig::from_pem(pem, suites)?));
    ClientConnection::new(Arc::new(config), server_name).map_err(EchPemError::Tls)
}

/// Creates a userspace server connection with shared-mode ECH.
///
/// Installs `decryption` keys and `retry` configurations and preserves the
/// other server settings. Shared mode requires `config.ech_backend` to be
/// false. Returns PEM setup or TLS construction errors.
pub fn prepare_server(
    mut config: ServerConfig,
    decryption: &[EchPem],
    retry: &[EchPem],
    suites: &[&'static dyn Hpke],
) -> Result<ServerConnection, EchPemError> {
    config.ech = Some(Arc::new(EchServerConfig::from_pems(
        decryption, retry, suites,
    )?));
    ServerConnection::new(Arc::new(config)).map_err(EchPemError::Tls)
}
