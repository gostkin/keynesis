use crate::{
    hash::Hash,
    key::ed25519::PublicKey,
    noise::{CipherState, CipherStateError},
};

/// Noise transport session between 2 participant. Communication is
/// Asymmetric. So it is possible to send messages independently from
/// the messages to receive. This allows to continue sending our current
/// messages without having to make sure we are in sync with the remote
/// messages.
///
/// All messages are authenticated and because we are rekeying after
/// each messages we have strong forward secrecy.
pub struct TransportState<H: Hash> {
    handshake_hash: H::HASH,
    local: CipherState,
    remote: CipherState,
    remote_id: PublicKey,
}

pub struct TransportSendHalf<H: Hash> {
    handshake_hash: H::HASH,
    local: CipherState,
    remote_id: PublicKey,
}

pub struct TransportReceiveHalf<H: Hash> {
    handshake_hash: H::HASH,
    remote: CipherState,
    remote_id: PublicKey,
}

impl<H: Hash> TransportState<H> {
    pub(crate) fn new(
        handshake_hash: H::HASH,
        local: CipherState,
        remote: CipherState,
        remote_id: PublicKey,
    ) -> Self {
        TransportState {
            handshake_hash,
            local,
            remote,
            remote_id,
        }
    }

    /// split the transport state into a sending half and receiving half
    ///
    /// this is to make it easier to handle bidirectional connections
    /// asynchronously.
    pub fn split(self) -> (TransportSendHalf<H>, TransportReceiveHalf<H>) {
        let Self {
            handshake_hash,
            local,
            remote,
            remote_id,
        } = self;
        let send = TransportSendHalf {
            handshake_hash: handshake_hash.clone(),
            local,
            remote_id,
        };

        let receive = TransportReceiveHalf {
            handshake_hash,
            remote,
            remote_id,
        };

        (send, receive)
    }

    /// unique identifier of the noise session
    pub fn noise_session(&self) -> &H::HASH {
        &self.handshake_hash
    }

    /// get the remote's public identity
    pub fn remote_public_identity(&self) -> &PublicKey {
        &self.remote_id
    }

    /// get the number of message received from the remote peer
    ///
    /// this function will be a little tainted by the handshake state
    /// it also account for the number of times either encrypt or
    /// decrypt has been used during the handshake. This is because
    /// during the handshake the exchange is symmetrical while in the
    /// transport era the exchanges are asymmetrical.
    pub fn count_received(&self) -> u64 {
        self.remote.nonce().into_u64()
    }

    /// get the number of message sent to the remote peer
    ///
    /// this function will be a little tainted by the handshake state
    /// it also account for the number of times either encrypt or
    /// decrypt has been used during the handshake. This is because
    /// during the handshake the exchange is symmetrical while in the
    /// transport era the exchanges are asymmetrical.
    pub fn count_sent(&self) -> u64 {
        self.local.nonce().into_u64()
    }

    /// send message to the remote peer
    ///
    /// The output must be at least 16 bytes longer than the input
    /// this is in order to add the MAC, this will be use to authenticate
    /// the message has not been tempered with.
    pub fn send(
        &mut self,
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.local.encrypt_with_ad(&[], input, output)?;
        self.local.rekey();

        Ok(())
    }

    /// receive message from the remote peer
    ///
    /// The output can have 16 bytes less than the input. This is because
    /// the MAC is appended in the input message so we can verify the
    /// message has not been tempered with.
    pub fn receive(
        &mut self,
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.remote.decrypt_with_ad(&[], input, output)?;
        self.remote.rekey();

        Ok(())
    }
}

impl<H: Hash> TransportSendHalf<H> {
    /// unique identifier of the noise session
    pub fn noise_session(&self) -> &H::HASH {
        &self.handshake_hash
    }

    /// get the remote's public identity
    pub fn remote_public_identity(&self) -> &PublicKey {
        &self.remote_id
    }

    /// get the number of message sent to the remote peer
    ///
    /// this function will be a little tainted by the handshake state
    /// it also account for the number of times either encrypt or
    /// decrypt has been used during the handshake. This is because
    /// during the handshake the exchange is symmetrical while in the
    /// transport era the exchanges are asymmetrical.
    pub fn count_sent(&self) -> u64 {
        self.local.nonce().into_u64()
    }

    /// send message to the remote peer
    ///
    /// The output must be at least 16 bytes longer than the input
    /// this is in order to add the MAC, this will be use to authenticate
    /// the message has not been tempered with.
    pub fn send(
        &mut self,
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.local.encrypt_with_ad(&[], input, output)?;
        self.local.rekey();

        Ok(())
    }
}

impl<H: Hash> TransportReceiveHalf<H> {
    /// unique identifier of the noise session
    pub fn noise_session(&self) -> &H::HASH {
        &self.handshake_hash
    }

    /// get the remote's public identity
    pub fn remote_public_identity(&self) -> &PublicKey {
        &self.remote_id
    }

    /// get the number of message received from the remote peer
    ///
    /// this function will be a little tainted by the handshake state
    /// it also account for the number of times either encrypt or
    /// decrypt has been used during the handshake. This is because
    /// during the handshake the exchange is symmetrical while in the
    /// transport era the exchanges are asymmetrical.
    pub fn count_received(&self) -> u64 {
        self.remote.nonce().into_u64()
    }

    /// receive message from the remote peer
    ///
    /// The output can have 16 bytes less than the input. This is because
    /// the MAC is appended in the input message so we can verify the
    /// message has not been tempered with.
    pub fn receive(
        &mut self,
        input: impl AsRef<[u8]>,
        output: &mut [u8],
    ) -> Result<(), CipherStateError> {
        self.remote.decrypt_with_ad(&[], input, output)?;
        self.remote.rekey();

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn test_transport<H: Hash>(
        mut initiator: TransportState<H>,
        mut responder: TransportState<H>,
        messages_init_to_responder: Vec<Vec<u8>>,
        messages_resp_to_initiator: Vec<Vec<u8>>,
    ) -> bool {
        for message in messages_init_to_responder {
            let mut output = vec![0; message.len() + CipherState::TAG_LEN];
            initiator
                .send(&message, &mut output)
                .expect("send encrypted message");

            let input = output;
            let mut output = vec![0; message.len()];
            responder
                .receive(&input, &mut output)
                .expect("receive message");

            assert!(message == output, "decryption of the message failed")
        }

        for message in messages_resp_to_initiator {
            let mut output = vec![0; message.len() + CipherState::TAG_LEN];
            responder
                .send(&message, &mut output)
                .expect("send encrypted message");

            let input = output;
            let mut output = vec![0; message.len()];
            initiator
                .receive(&input, &mut output)
                .expect("receive message");

            assert!(message == output, "decryption of the message failed")
        }

        true
    }
}
