use std::i16::MAX;

use crate::hash::Algorithm;
use rustls::crypto::hash::Hash as _;
use rustls::crypto::hmac::{Key, Tag};
use windows::core::Array;
use windows::Security::Cryptography::Core::{
    CryptographicKey, MacAlgorithmNames, MacAlgorithmProvider,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;

#[derive(Clone, Debug, Copy)]
pub(crate) struct Hmac(pub(crate) Algorithm);

impl Hmac {
    fn mac_algorithm_provider(&self) -> MacAlgorithmProvider {
        let name = match self.0 {
            Algorithm::SHA256 => MacAlgorithmNames::HmacSha256().unwrap(),
            Algorithm::SHA384 => MacAlgorithmNames::HmacSha384().unwrap(),
        };
        MacAlgorithmProvider::OpenAlgorithm(&name).unwrap()
    }

    fn max_key_len(&self) -> usize {
        match self.0 {
            Algorithm::SHA256 => 64,
            Algorithm::SHA384 => 128,
        }
    }
}

const MAX_KEY_LEN: usize = 128;
struct HmacKey {
    key: [u8; MAX_KEY_LEN],
    size: usize,
    hmac: Hmac,
}

impl rustls::crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        let mut key_buffer = [0u8; MAX_KEY_LEN];

        if key.len() <= self.max_key_len() {
            key_buffer[..key.len()].copy_from_slice(key);
            Box::new(HmacKey {
                key: key_buffer,
                size: key.len(),
                hmac: *self,
            })
        } else {
            // hash the key if it is too long
            let output = self.0.hash(key);
            key_buffer[..output.as_ref().len()].copy_from_slice(output.as_ref());
            Box::new(HmacKey {
                key: key_buffer,
                size: output.as_ref().len(),
                hmac: *self,
            })
        }
    }

    fn hash_output_len(&self) -> usize {
        self.0.output_len()
    }
}

impl Key for HmacKey {
    fn sign(&self, data: &[&[u8]]) -> Tag {
        self.sign_concat(&[], data, &[])
    }

    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let key_buffer = CryptographicBuffer::CreateFromByteArray(&self.key[..self.size]).unwrap();
        let hash = self
            .hmac
            .mac_algorithm_provider()
            .CreateHash(&key_buffer)
            .unwrap();

        let first = CryptographicBuffer::CreateFromByteArray(first).unwrap();
        hash.Append(&first).unwrap();
        for d in middle {
            let d = CryptographicBuffer::CreateFromByteArray(d).unwrap();
            hash.Append(&d).unwrap();
        }
        let last = CryptographicBuffer::CreateFromByteArray(last).unwrap();
        hash.Append(&last).unwrap();

        let tag_buffer = hash.GetValueAndReset().unwrap();
        let mut tag = [0u8; MAX_KEY_LEN];
        let tag_length = tag_buffer.Length().unwrap() as usize;
        let mut tag_array = Array::<u8>::with_len(tag_length);

        CryptographicBuffer::CopyToByteArray(&tag_buffer, &mut tag_array).unwrap();
        tag[..tag_length].copy_from_slice(tag_array.as_slice());
        Tag::new(&tag[..tag_length])
    }

    fn tag_len(&self) -> usize {
        self.hmac.0.output_len()
    }
}

#[cfg(test)]
mod test {
    use crate::{hash::Algorithm, hmac::Hmac};
    use rustls::crypto::hmac::{Hmac as _, Tag};
    use wycheproof::TestResult;

    fn test_hmac(alg: Algorithm) {
        let test_name = match alg {
            Algorithm::SHA256 => wycheproof::mac::TestName::HmacSha256,
            Algorithm::SHA384 => wycheproof::mac::TestName::HmacSha384,
        };
        let test_set = wycheproof::mac::TestSet::load(test_name).unwrap();

        let mut counter = 0;

        for group in test_set.test_groups.into_iter() {
            for test in group.tests {
                counter += 1;

                let hmac = Hmac(alg);
                let key = hmac.with_key(&test.key);
                let actual_tag = key.sign(&[&test.msg]);

                let expected_tag = if test.tag.len() <= Tag::MAX_LEN {
                    &test.tag[..]
                } else {
                    &test.tag[..Tag::MAX_LEN]
                };

                let actual_tag = if expected_tag.len() < actual_tag.as_ref().len() {
                    &actual_tag.as_ref()[..expected_tag.len()]
                } else {
                    &actual_tag.as_ref()
                };

                match &test.result {
                    TestResult::Invalid => {
                        assert_ne!(
                            actual_tag.as_ref(),
                            expected_tag,
                            "Expected incorrect tag. Id {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                    TestResult::Valid | TestResult::Acceptable => {
                        assert_eq!(
                            actual_tag.as_ref(),
                            expected_tag,
                            "Incorrect tag on testcase {}: {}",
                            test.tc_id,
                            test.comment
                        );
                    }
                }
            }
        }

        // Ensure we ran some tests.
        assert!(counter > 50);
    }

    #[test]
    fn test_sha256() {
        test_hmac(Algorithm::SHA256);
    }

    #[test]
    fn test_sha384() {
        test_hmac(Algorithm::SHA384);
    }
}
