use std::i16::MAX;

use crate::hash::{Algorithm, Context};
use rustls::crypto::hash::{Context as _, Hash as _, HashAlgorithm};
use rustls::crypto::hmac::{Key, Tag};
use windows::core::{Array, Owned};
use windows::Security::Cryptography::Core::{
    CryptographicKey, MacAlgorithmNames, MacAlgorithmProvider,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::IBuffer;
use windows::Win32::Security::Cryptography::{
    BCryptCreateHash, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE_HMAC_FLAG,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
};

impl<const SIZE: usize> rustls::crypto::hmac::Hmac for Algorithm<SIZE> {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        let mut alg_handle = Owned::default();
        let mut hash_handle = Owned::default();
        unsafe {
            BCryptOpenAlgorithmProvider(
                &mut *alg_handle,
                self.id,
                None,
                BCRYPT_ALG_HANDLE_HMAC_FLAG,
            )
            .ok()
            .unwrap();
            BCryptCreateHash(*alg_handle, &mut *hash_handle, None, Some(key), 0)
                .ok()
                .unwrap();
        }
        Box::new(Context::<SIZE> {
            alg: *self,
            handle: hash_handle,
        })
    }

    fn hash_output_len(&self) -> usize {
        SIZE
    }
}

impl<const SIZE: usize> Key for Context<SIZE> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut new = self.fork();
        new.update(first);
        for d in middle {
            new.update(d);
        }
        new.update(last);
        Tag::new(new.finish().as_ref())
    }

    fn tag_len(&self) -> usize {
        SIZE
    }
}

#[cfg(test)]
mod test {
    use crate::hash::{Algorithm, SHA256, SHA384};
    use rustls::crypto::hmac::{Hmac as _, Tag};
    use wycheproof::TestResult;

    #[rstest::rstest]
    #[case(SHA256)]
    #[case(SHA384)]
    fn hmac<const SIZE: usize>(#[case] alg: Algorithm<SIZE>) {
        let test_name = match alg.rustls_algorithm {
            rustls::crypto::hash::HashAlgorithm::SHA256 => wycheproof::mac::TestName::HmacSha256,
            rustls::crypto::hash::HashAlgorithm::SHA384 => wycheproof::mac::TestName::HmacSha384,
            _ => panic!("Unsupported algorithm"),
        };
        let test_set = wycheproof::mac::TestSet::load(test_name).unwrap();

        let mut counter = 0;

        for group in test_set.test_groups.into_iter() {
            for test in group.tests {
                counter += 1;

                let key = alg.with_key(&test.key);
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
}
