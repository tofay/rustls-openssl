use crate::{aead, cipher::CipherKind};
use openssl::{cipher::CipherRef, cipher_ctx::CipherCtx};
use rustls::{
    Error,
    crypto::cipher::{AeadKey, Iv, Nonce},
    quic,
};

pub(crate) struct KeyBuilder {
    pub(crate) packet_algo: aead::Algorithm,
    pub(crate) header_algo: HeaderProtectionAlgorithm,
    pub(crate) confidentiality_limit: u64,
    pub(crate) integrity_limit: u64,
}

/// A QUIC packet protection key.
struct PacketKey {
    algo: aead::Algorithm,
    key: AeadKey,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

/// A QUIC header protection algorithm.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HeaderProtectionAlgorithm {
    Aes128,
    Aes256,
    ChaCha20,
}

pub(crate) struct HeaderProtectionKey {
    algo: HeaderProtectionAlgorithm,
    key: AeadKey,
}

/// The Sample length is 16 bytes for all supported ciphers.
const SAMPLE_LEN: usize = 16;

impl quic::Algorithm for KeyBuilder {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            algo: self.packet_algo,
            key,
            iv,
            confidentiality_limit: self.confidentiality_limit,
            integrity_limit: self.integrity_limit,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey {
            algo: self.header_algo,
            key,
        })
    }

    fn aead_key_len(&self) -> usize {
        self.packet_algo.key_size()
    }

    fn fips(&self) -> bool {
        crate::fips::enabled()
    }
}

impl quic::PacketKey for PacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let tag = self.algo.encrypt_in_place(
            self.key.as_ref(),
            &Nonce::new(&self.iv, packet_number).0,
            header,
            payload,
        )?;
        Ok(quic::Tag::from(tag.as_ref()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plaintext_len = self.algo.decrypt_in_place(
            self.key.as_ref(),
            &Nonce::new(&self.iv, packet_number).0,
            header,
            payload,
        )?;
        Ok(&payload[..plaintext_len])
    }

    fn tag_len(&self) -> usize {
        aead::TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

impl quic::HeaderProtectionKey for HeaderProtectionKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        // Implement https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
        let mask = self.mask(sample)?;

        let (first_mask, packet_number_mask) = mask.split_first().expect("mask is 5 bytes long");
        if packet_number_mask.len() < packet_number.len() {
            return Err(Error::General("packet number exceeds 4 bytes".into()));
        }
        let packet_number_length = (*first & 0x03) + 1;
        if (*first & 0x80) == 0x80 {
            // Long header: 4 bits masked
            *first ^= first_mask & 0x0f;
        } else {
            // Short header: 5 bits masked
            *first ^= first_mask & 0x1f;
        }

        packet_number
            .iter_mut()
            .zip(packet_number_mask)
            .take(packet_number_length as usize)
            .for_each(|(packet_number_byte, mask)| *packet_number_byte ^= mask);

        Ok(())
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        // Reverse https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
        let mask = self.mask(sample)?;

        let (first_mask, packet_number_mask) = mask.split_first().expect("mask is 5 bytes long");
        if packet_number_mask.len() < packet_number.len() {
            return Err(Error::General("packet number exceeds 4 bytes".into()));
        }
        if (*first & 0x80) == 0x80 {
            // Long header: 4 bits masked
            *first ^= first_mask & 0x0f;
        } else {
            // Short header: 5 bits masked
            *first ^= first_mask & 0x1f;
        }
        // When decrypting, determine the packet number length *after* unmasking the first byte.
        let packet_number_length = (*first & 0x03) + 1;

        packet_number
            .iter_mut()
            .zip(packet_number_mask)
            .take(packet_number_length as usize)
            .for_each(|(packet_number_byte, mask)| *packet_number_byte ^= mask);
        Ok(())
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

impl HeaderProtectionAlgorithm {
    fn load(self) -> Result<&'static CipherRef, Error> {
        let kind = match self {
            HeaderProtectionAlgorithm::Aes128 => CipherKind::Aes128Ecb,
            HeaderProtectionAlgorithm::Aes256 => CipherKind::Aes256Ecb,
            HeaderProtectionAlgorithm::ChaCha20 => CipherKind::ChaCha20,
        };
        kind.load()
    }
}

impl HeaderProtectionKey {
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let mut mask = [0; 5];
        let cipher = self.algo.load()?;
        let block = CipherCtx::new()
            .and_then(|mut ctx| {
                match self.algo {
                    // https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.3
                    HeaderProtectionAlgorithm::Aes128 | HeaderProtectionAlgorithm::Aes256 => {
                        ctx.encrypt_init(Some(cipher), Some(self.key.as_ref()), None)?;
                        ctx.set_padding(false);
                        let mut out = vec![0; sample.len() + cipher.block_size()];
                        let count = ctx.cipher_update(sample, Some(&mut out))?;
                        let rest = ctx.cipher_final(&mut out[count..])?;
                        out.truncate(count + rest);
                        Ok(out)
                    }
                    // https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.4
                    HeaderProtectionAlgorithm::ChaCha20 => {
                        ctx.encrypt_init(Some(cipher), Some(self.key.as_ref()), Some(sample))?;
                        let mut out = vec![0; 5 + cipher.block_size()];
                        let count = ctx.cipher_update(&[0; 5], Some(&mut out))?;
                        let rest = ctx.cipher_final(&mut out[count..])?;
                        out.truncate(count + rest);
                        Ok(out)
                    }
                }
            })
            .map_err(|e| Error::General(format!("OpenSSL error: {e}")))?;
        mask.copy_from_slice(&block[..5]);
        Ok(mask)
    }
}

#[cfg(test)]
mod test {
    use rustls::{
        Side,
        quic::{HeaderProtectionKey, Keys, Version},
    };

    use crate::cipher::CipherKind;

    use super::super::tls13::TLS13_AES_128_GCM_SHA256_INTERNAL;

    // https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.3
    #[test]
    fn initial_test_vector_v1_server() {
        let icid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let server = Keys::initial(
            Version::V1,
            TLS13_AES_128_GCM_SHA256_INTERNAL,
            TLS13_AES_128_GCM_SHA256_INTERNAL.quic.unwrap(),
            &icid,
            Side::Server,
        );

        // Identical CRYPTO-frame payload to initial_test_vector_v2 —
        // only the QUIC-layer key schedule differs between v1/v2, not the TLS content.
        let mut server_payload = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
            0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
            0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
            0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
            0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
            0x04,
        ];

        // RFC 9001 §A.3: "c1000000010008f067a5502a4262b50040750001"
        let mut server_header = [
            0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
        ];

        let tag = server
            .local
            .packet
            .encrypt_in_place(1, &server_header, &mut server_payload)
            .unwrap();

        let (first, rest) = server_header.split_at_mut(1);
        let rest_len = rest.len();
        server
            .local
            .header
            .encrypt_in_place(
                &server_payload[2..18],
                &mut first[0],
                &mut rest[rest_len - 2..],
            )
            .unwrap();

        let mut server_packet = server_header.to_vec();
        server_packet.extend(server_payload);
        server_packet.extend(tag.as_ref());

        // RFC 9001 §A.3 final protected packet.
        let expected_server_packet = [
            0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0xc0, 0xd9, 0x5a, 0x48, 0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b,
            0x0a, 0xac, 0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39, 0x41, 0x00, 0xf3, 0x7a, 0x1c, 0x69,
            0x79, 0x75, 0x54, 0x78, 0x0b, 0xb3, 0x8c, 0xc5, 0xa9, 0x9f, 0x5e, 0xde, 0x4c, 0xf7,
            0x3c, 0x3e, 0xc2, 0x49, 0x3a, 0x18, 0x39, 0xb3, 0xdb, 0xcb, 0xa3, 0xf6, 0xea, 0x46,
            0xc5, 0xb7, 0x68, 0x4d, 0xf3, 0x54, 0x8e, 0x7d, 0xde, 0xb9, 0xc3, 0xbf, 0x9c, 0x73,
            0xcc, 0x3f, 0x3b, 0xde, 0xd7, 0x4b, 0x56, 0x2b, 0xfb, 0x19, 0xfb, 0x84, 0x02, 0x2f,
            0x8e, 0xf4, 0xcd, 0xd9, 0x37, 0x95, 0xd7, 0x7d, 0x06, 0xed, 0xbb, 0x7a, 0xaf, 0x2f,
            0x58, 0x89, 0x18, 0x50, 0xab, 0xbd, 0xca, 0x3d, 0x20, 0x39, 0x8c, 0x27, 0x64, 0x56,
            0xcb, 0xc4, 0x21, 0x58, 0x40, 0x7d, 0xd0, 0x74, 0xee,
        ];

        assert_eq!(server_packet[..], expected_server_packet[..]);
    }

    // Taken from rustls: Copyright (c) 2016 Joseph Birr-Pixton <jpixton@gmail.com>
    #[test]
    fn initial_test_vector_v2() {
        // https://www.ietf.org/archive/id/draft-ietf-quic-v2-10.html#name-sample-packet-protection-2
        let icid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let server = Keys::initial(
            Version::V2,
            TLS13_AES_128_GCM_SHA256_INTERNAL,
            TLS13_AES_128_GCM_SHA256_INTERNAL.quic.unwrap(),
            &icid,
            Side::Server,
        );
        let mut server_payload = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
            0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
            0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
            0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
            0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
            0x04,
        ];
        let mut server_header = [
            0xd1, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0x00, 0x01,
        ];
        let tag = server
            .local
            .packet
            .encrypt_in_place(1, &server_header, &mut server_payload)
            .unwrap();
        let (first, rest) = server_header.split_at_mut(1);
        let rest_len = rest.len();
        server
            .local
            .header
            .encrypt_in_place(
                &server_payload[2..18],
                &mut first[0],
                &mut rest[rest_len - 2..],
            )
            .unwrap();
        let mut server_packet = server_header.to_vec();
        server_packet.extend(server_payload);
        server_packet.extend(tag.as_ref());
        let expected_server_packet = [
            0xdc, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0xd9, 0x2f, 0xaa, 0xf1, 0x6f, 0x05, 0xd8, 0xa4, 0x39, 0x8c,
            0x47, 0x08, 0x96, 0x98, 0xba, 0xee, 0xa2, 0x6b, 0x91, 0xeb, 0x76, 0x1d, 0x9b, 0x89,
            0x23, 0x7b, 0xbf, 0x87, 0x26, 0x30, 0x17, 0x91, 0x53, 0x58, 0x23, 0x00, 0x35, 0xf7,
            0xfd, 0x39, 0x45, 0xd8, 0x89, 0x65, 0xcf, 0x17, 0xf9, 0xaf, 0x6e, 0x16, 0x88, 0x6c,
            0x61, 0xbf, 0xc7, 0x03, 0x10, 0x6f, 0xba, 0xf3, 0xcb, 0x4c, 0xfa, 0x52, 0x38, 0x2d,
            0xd1, 0x6a, 0x39, 0x3e, 0x42, 0x75, 0x75, 0x07, 0x69, 0x80, 0x75, 0xb2, 0xc9, 0x84,
            0xc7, 0x07, 0xf0, 0xa0, 0x81, 0x2d, 0x8c, 0xd5, 0xa6, 0x88, 0x1e, 0xaf, 0x21, 0xce,
            0xda, 0x98, 0xf4, 0xbd, 0x23, 0xf6, 0xfe, 0x1a, 0x3e, 0x2c, 0x43, 0xed, 0xd9, 0xce,
            0x7c, 0xa8, 0x4b, 0xed, 0x85, 0x21, 0xe2, 0xe1, 0x40,
        ];
        assert_eq!(server_packet[..], expected_server_packet[..]);
    }

    // https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.5
    #[test]
    fn chacha20_poly1305_short_header_packet() {
        if !CipherKind::ChaCha20Poly1305.is_available() || !CipherKind::ChaCha20.is_available() {
            return;
        }

        use rustls::crypto::cipher::AeadKey;

        let key_bytes = [
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c,
            0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79,
            0xfb, 0x23, 0xe1, 0xc8,
        ];
        // RFC's "nonce" is already iv XOR packet_number; encrypt_in_place expects the raw
        // per-packet nonce, so we pass this directly rather than deriving it via Nonce::new.
        let nonce = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x6d, 0x41, 0x7e, 0xb0,
        ];
        let unprotected_header = [0x42, 0x00, 0xbf, 0xf4];
        let mut payload = vec![0x01]; // single PING frame

        let tag = crate::aead::Algorithm::ChaCha20Poly1305
            .encrypt_in_place(&key_bytes, &nonce, &unprotected_header, &mut payload)
            .unwrap();

        let mut ciphertext = payload;
        ciphertext.extend_from_slice(tag.as_ref());

        let expected_ciphertext = [
            0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2,
            0x5a, 0x5b, 0xfb,
        ];
        assert_eq!(ciphertext[..], expected_ciphertext[..]);

        // Header protection: sample is bytes [1..17] of the ciphertext.
        let sample = &ciphertext[1..17];
        let hpk = super::HeaderProtectionKey {
            algo: super::HeaderProtectionAlgorithm::ChaCha20,
            key: AeadKey::from([
                0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
                0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
                0x0a, 0xb7, 0xa7, 0xa4,
            ]),
        };

        let mut header = unprotected_header;
        let (first, rest) = header.split_at_mut(1);
        hpk.encrypt_in_place(sample, &mut first[0], rest).unwrap();

        assert_eq!(header, [0x4c, 0xfe, 0x41, 0x89]);

        let mut packet = header.to_vec();
        packet.extend_from_slice(&ciphertext);
        let expected_packet = [
            0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57,
            0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
        ];
        assert_eq!(packet[..], expected_packet[..]);
    }

    // https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.2
    #[test]
    fn initial_test_vector_v1_client() {
        // Strips whitespace/newlines so RFC hex blocks can be pasted verbatim,
        // exactly as formatted in the spec, instead of hand-regrouped into 0x.. literals.
        fn from_hex(s: &str) -> Vec<u8> {
            let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
            clean
                .chunks(2)
                .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect()
        }

        let icid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let client = Keys::initial(
            Version::V1,
            TLS13_AES_128_GCM_SHA256_INTERNAL,
            TLS13_AES_128_GCM_SHA256_INTERNAL.quic.unwrap(),
            &icid,
            Side::Client,
        );

        // CRYPTO frame (ClientHello) from RFC 9001 §A.2, pasted verbatim.
        let crypto_frame = from_hex(
            "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
         04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
         616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
         04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
         baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
         0d0010000e0403050306030203080408 050806002d00020101001c0002400100
         3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
         75300901100f088394c8f03e51570806 048000ffff",
        );

        // Padded to 1162 bytes with PADDING frames (0x00), per RFC 9001 §A.2.
        // Length is computed here rather than hand-counted, to avoid an off-by-one
        // in a hand-transcribed 1162-byte figure.
        let mut client_payload = crypto_frame;
        client_payload.resize(1162, 0);

        // Unprotected header: c3 (long header, Initial, 4-byte PN) | version | DCID len/DCID
        // | SCID len=0 | token len=0 | length=0x449e (varint) | packet number = 2 (4 bytes).
        let mut client_header = [
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
        ];

        let tag = client
            .local
            .packet
            .encrypt_in_place(2, &client_header, &mut client_payload)
            .unwrap();

        // pn_length = 4 here (unlike the 2-byte-pn V2/A.3 tests), so the header-protection
        // sample starts at ciphertext offset (4 - pn_len) = 0, and the packet-number mask
        // applies to the last 4 bytes of the header, not the last 2.
        let (first, rest) = client_header.split_at_mut(1);
        let rest_len = rest.len();
        client
            .local
            .header
            .encrypt_in_place(
                &client_payload[0..16],
                &mut first[0],
                &mut rest[rest_len - 4..],
            )
            .unwrap();

        let mut client_packet = client_header.to_vec();
        client_packet.extend(client_payload);
        client_packet.extend(tag.as_ref());

        let expected_client_packet = from_hex(
            "c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
         d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
         1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
         8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
         30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
         457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
         4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
         4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
         485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
         059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
         7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
         9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
         be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
         68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
         c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
         f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
         291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
         25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
         14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
         ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
         e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
         c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
         203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
         cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
         fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
         a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
         90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
         162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
         40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
         6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
         8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
         be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
         54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
         760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
         f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
         056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
         7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
         e221af44860018ab0856972e194cd934",
        );
        assert_eq!(expected_client_packet.len(), 1200); // payload + header + tag

        assert_eq!(client_packet, expected_client_packet);
    }
}
