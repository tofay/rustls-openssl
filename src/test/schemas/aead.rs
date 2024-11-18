use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AeadTestFile {
    /// the primitive tested in the test file
    pub algorithm: Option<String>,
    /// the version of the test vectors.
    pub generator_version: Option<String>,
    /// additional documentation
    pub header: Option<Vec<String>>,
    /// a description of the labels used in the test vectors
    pub notes: Option<HashMap<String, Option<serde_json::Value>>>,
    /// the number of test vectors in this test
    pub number_of_tests: Option<i64>,
    pub schema: Option<Schema>,
    pub test_groups: Option<Vec<AeadTestGroup>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Schema {
    #[serde(rename = "aead_test_schema.json")]
    AeadTestSchemaJson,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AeadTestGroup {
    /// the IV size in bits
    pub iv_size: Option<i64>,
    /// the keySize in bits
    pub key_size: Option<i64>,
    /// the expected size of the tag in bits
    pub tag_size: Option<i64>,
    pub tests: Option<Vec<AeadTestVector>>,
    #[serde(rename = "type")]
    pub aead_test_group_type: Option<Type>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "AeadTest")]
    AeadTest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AeadTestVector {
    /// additional authenticated data
    pub aad: Option<String>,
    /// A brief description of the test case
    pub comment: Option<String>,
    /// the ciphertext (without iv and tag)
    pub ct: Option<String>,
    /// A list of flags
    pub flags: Option<Vec<String>>,
    /// the nonce
    pub iv: Option<String>,
    /// the key
    pub key: Option<String>,
    /// the plaintext
    pub msg: Option<String>,
    /// Test result
    pub result: Option<Result>,
    /// the authentication tag
    pub tag: Option<String>,
    /// Identifier of the test case
    pub tc_id: Option<i64>,
}

/// Test result
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Result {
    Acceptable,
    Invalid,
    Valid,
}
