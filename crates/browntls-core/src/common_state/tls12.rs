//! TLS 1.2 cipher activation for stream and datagram connections.

use super::{CommonState, Side};
use crate::enums::ProtocolVersion;
use crate::msgs::message::{Message, MessagePayload};

impl CommonState {
    /// TLS 1.2: installs the record ciphers derived from `secrets`. Encryption
    /// starts when we send ChangeCipherSpec; decryption when we receive it.
    #[cfg(feature = "tls12")]
    pub(crate) fn start_encryption_tls12(
        &mut self,
        secrets: &crate::tls12::ConnectionSecrets,
        side: Side,
        order: crate::crypto::cipher::Tls12MacOrder,
    ) {
        let pair = secrets.make_cipher_pair(side, order);
        if let Some(dtls) = &mut self.dtls {
            dtls.prepare_v12(
                pair.enc,
                pair.dec,
                secrets.suite().common.confidentiality_limit,
            );
            return;
        }
        self.record_layer
            .prepare_message_encrypter(pair.enc, secrets.suite().common.confidentiality_limit);
        self.record_layer.prepare_message_decrypter(pair.dec);
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn start_decrypting_tls12(&mut self) {
        if let Some(dtls) = &mut self.dtls {
            dtls.activate_v12_read();
        } else {
            self.record_layer.start_decrypting();
        }
    }

    /// Sends ChangeCipherSpec and starts encrypting (TLS 1.2).
    #[cfg(feature = "tls12")]
    pub(crate) fn send_change_cipher_spec(&mut self) {
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(crate::msgs::ccs::ChangeCipherSpecPayload),
        };
        self.send_msg(m, false);
        if let Some(dtls) = &mut self.dtls {
            dtls.activate_v12_write();
        } else {
            self.record_layer.start_encrypting();
        }
    }
}
