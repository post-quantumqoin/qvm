// Copyright 2021-2023 Protocol Labs
// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::borrow::Cow;
use std::error;

use fvm_ipld_encoding::tuple::*;
use fvm_ipld_encoding::repr::*;
use fvm_ipld_encoding::{de, ser, strict_bytes, Error as EncodingError};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

use crate::address::Error as AddressError;


/// BLS signature length in bytes.
pub const BLS_SIG_LEN: usize = 96;
/// BLS Public key length in bytes.
pub const BLS_PUB_LEN: usize = 48;

/// Secp256k1 signature length in bytes.
pub const SECP_SIG_LEN: usize = 65;
/// Secp256k1 Public key length in bytes.
pub const SECP_PUB_LEN: usize = 65;
/// Length of the signature input message hash in bytes (32).
pub const SECP_SIG_MESSAGE_HASH_SIZE: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct SignPqcCertPubkey {
	pub typ: String,
    #[serde(with = "strict_bytes")]
	pub pubkey: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize_tuple, Deserialize_tuple)]
pub struct SignPQCCert  {
	pub pubkeys: Vec<SignPqcCertPubkey>,
	pub version: u64,
	// Nonce   []byte
}
// extern "C" {
//     pub fn falcon512_verify(
//         m: *const u8,  
//         mlen: i32, 
//         sm: *const u8, 
//         pk: *const u8
//     )-> i32;

//     pub fn falcon1024_verify(
//         m: *const u8,  
//         mlen: i32, 
//         sm: *const u8, 
//         pk: *const u8
//     )-> i32;

//     pub fn dilithium3_crypto_sign_verify(
//         m: *const u8, 
//         sm: *const u8, 
//         mlen: i32,  
//         pk: *const u8
//     )-> i32;

//     pub fn dilithium5_crypto_sign_verify(
//         m: *const u8, 
//         sm: *const u8, 
//         mlen: i32,  
//         pk: *const u8
//     )-> i32;
// }
// fn pqc_falcon512_verify(
//     m: &[u8],
//     sm: &[u8],
//     pk: &[u8],
// ) -> bool {
//     unsafe {
//         if falcon512_verify(
//             m.as_ptr(),
//             m.len() as i32,
//             sm.as_ptr(),
//             pk.as_ptr(),
//         ) == 0{
//             true
//         }else{
//             false
//         }
//     }
// }

// fn pqc_falcon1024_verify(
//     m: &[u8],
//     sm: &[u8],
//     pk: &[u8],
// ) -> bool {
//     unsafe {
//         if falcon1024_verify(
//             m.as_ptr(),
//             m.len() as i32,
//             sm.as_ptr(),
//             pk.as_ptr(),
//         ) == 0{
//             true
//         }else{
//             false
//         }
//     }
// }

// fn pqc_dilithium3_verify(
//     m: &[u8],
//     sm: &[u8],
//     pk: &[u8],
// ) -> bool {
//     unsafe {
//         if dilithium3_crypto_sign_verify(
//             m.as_ptr(),
//             sm.as_ptr(),
//             sm.len() as i32,
//             pk.as_ptr(),
//         ) == 0{
//             true
//         }else{
//             false
//         }
//     }
// }

// fn pqc_dilithium5_verify(
//     m: &[u8],
//     sm: &[u8],
//     pk: &[u8],
// ) -> bool {
//     unsafe {
//         if dilithium5_crypto_sign_verify(
//             m.as_ptr(),
//             sm.as_ptr(),
//             sm.len() as i32,
//             pk.as_ptr(),
//         ) == 0{
//             true
//         }else{
//             false
//         }
//     }
// }
/// Signature variants for Filecoin signatures.
#[derive(
    Clone, Debug, PartialEq, FromPrimitive, Copy, Eq, Serialize_repr, Deserialize_repr, Hash,
)]
#[repr(u8)]
pub enum SignatureType {
    Secp256k1 = 1,
    BLS = 2,
    Delegated=3,
	MultiPqc=4,

	Falcon512=5,
	Falcon1024=6,
	Dilithium3=7,
	Dilithium5=8,
}

/// A cryptographic signature, represented in bytes, of any key protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature {
    pub sig_type: SignatureType,
    pub bytes: Vec<u8>,
}

impl ser::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let mut bytes = Vec::with_capacity(self.bytes.len() + 1);
        // Insert signature type byte
        bytes.push(self.sig_type as u8);
        bytes.extend_from_slice(&self.bytes);

        strict_bytes::Serialize::serialize(&bytes, serializer)
    }
}

impl<'de> de::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: Cow<'de, [u8]> = strict_bytes::Deserialize::deserialize(deserializer)?;
        if bytes.is_empty() {
            return Err(de::Error::custom("Cannot deserialize empty bytes"));
        }

        // Remove signature type byte
        let sig_type = SignatureType::from_u8(bytes[0])
            .ok_or_else(|| de::Error::custom("Invalid signature type byte (must be 1 or 2)"))?;

        Ok(Signature {
            bytes: bytes[1..].to_vec(),
            sig_type,
        })
    }
}

impl Signature {
    /// Creates a SECP Signature given the raw bytes.
    pub fn new_secp256k1(bytes: Vec<u8>) -> Self {
        Self {
            sig_type: SignatureType::Secp256k1,
            bytes,
        }
    }

    /// Creates a BLS Signature given the raw bytes.
    pub fn new_bls(bytes: Vec<u8>) -> Self {
        Self {
            sig_type: SignatureType::BLS,
            bytes,
        }
    }

    /// Returns reference to signature bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns [SignatureType] for the signature.
    pub fn signature_type(&self) -> SignatureType {
        self.sig_type
    }
}

#[cfg(feature = "arb")]
impl quickcheck::Arbitrary for SignatureType {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        if bool::arbitrary(g) {
            SignatureType::Secp256k1
        } else {
            SignatureType::BLS
        }
    }
}

#[cfg(feature = "arb")]
impl quickcheck::Arbitrary for Signature {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        Self {
            bytes: Vec::arbitrary(g),
            sig_type: SignatureType::arbitrary(g),
        }
    }
}

#[cfg(feature = "crypto")]
impl Signature {
    /// Checks if a signature is valid given data and address.
    pub fn verify(&self, data: &[u8], rawaddr: &[u8],addr: &crate::address::Address) -> Result<(), String> {
        verify(self.sig_type, &self.bytes, data,rawaddr, addr)
    }
}

#[cfg(feature = "crypto")]
pub fn verify(
    sig_type: SignatureType,
    sig_data: &[u8],
    data: &[u8],
    rawaddr: &[u8],
    addr: &crate::address::Address,
) -> Result<(), String> {
    println!("crypto verify");
    match sig_type {
        SignatureType::BLS => self::ops::verify_bls_sig(sig_data, data, addr),
        SignatureType::Secp256k1 => self::ops::verify_secp256k1_sig(sig_data, data, addr),
        SignatureType::MultiPqc|SignatureType::Delegated => {
            Err(format!(
            "delegated and multiPqc types that shouldn't be here",
        ))},
        SignatureType::Falcon512 => self::ops::verify_falcon512_sig(sig_data, data, rawaddr),
        SignatureType::Falcon1024 => self::ops::verify_falcon1024_sig(sig_data, data, rawaddr),
        SignatureType::Dilithium3 => self::ops::verify_dilithium3_sig(sig_data, data, rawaddr),
        SignatureType::Dilithium5 => self::ops::verify_dilithium5_sig(sig_data, data, rawaddr),
    }
}

#[cfg(feature = "crypto")]
pub mod ops {
    use crate::crypto::pqc::{falcon512_verify,falcon1024_verify,dilithium3_crypto_sign_verify,dilithium5_crypto_sign_verify};
    use bls_signatures::{
        verify_messages, PublicKey as BlsPubKey, Serialize, Signature as BlsSignature,
    };
    use libsecp256k1::{
        recover, Error as SecpError, Message, PublicKey, RecoveryId, Signature as EcsdaSignature,
    };

    use super::{Error, SECP_SIG_LEN, SECP_SIG_MESSAGE_HASH_SIZE};
    use crate::address::{Address, Protocol};
    use crate::crypto::signature::Signature;

    /// Returns `String` error if a bls signature is invalid.
    pub fn verify_bls_sig(signature: &[u8], data: &[u8], addr: &Address) -> Result<(), String> {
        if addr.protocol() != Protocol::BLS {
            return Err(format!(
                "cannot validate a BLS signature against a {} address",
                addr.protocol()
            ));
        }

        let pub_k = addr.payload_bytes();

        // generate public key object from bytes
        let pk = BlsPubKey::from_bytes(&pub_k).map_err(|e| e.to_string())?;

        // generate signature struct from bytes
        let sig = BlsSignature::from_bytes(signature).map_err(|e| e.to_string())?;

        // BLS verify hash against key
        if verify_messages(&sig, &[data], &[pk]) {
            Ok(())
        } else {
            Err(format!(
                "bls signature verification failed for addr: {}",
                addr
            ))
        }
    }

    /// Returns `String` error if a secp256k1 signature is invalid.
    pub fn verify_secp256k1_sig(
        signature: &[u8],
        data: &[u8],
        addr: &Address,
    ) -> Result<(), String> {
        if addr.protocol() != Protocol::Secp256k1 {
            return Err(format!(
                "cannot validate a secp256k1 signature against a {} address",
                addr.protocol()
            ));
        }

        if signature.len() != SECP_SIG_LEN {
            return Err(format!(
                "Invalid Secp256k1 signature length. Was {}, must be 65",
                signature.len()
            ));
        }

        // blake2b 256 hash
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(data)
            .finalize();

        // Ecrecover with hash and signature
        let mut sig = [0u8; SECP_SIG_LEN];
        sig[..].copy_from_slice(signature);
        let rec_addr = ecrecover(hash.as_bytes().try_into().expect("fixed array size"), &sig)
            .map_err(|e| e.to_string())?;

        // check address against recovered address
        if &rec_addr == addr {
            Ok(())
        } else {
            Err("Secp signature verification failed".to_owned())
        }
    }

    pub fn verify_falcon512_sig(
        signature: &[u8],
        data: &[u8],
        rawaddr:&[u8],
    ) -> Result<(), String> {
        unsafe {
            match falcon512_verify(
                data.as_ptr(),
                data.len() as i32,
                signature.as_ptr(),
                rawaddr.as_ptr(),
            ) {
                0 => Ok(()),
                -1 => Err("falcon512 signature verification failed".to_owned()),
                _ => todo!(),
            }
        }
    }


    pub fn verify_falcon1024_sig(
        signature: &[u8],
        data: &[u8],
        rawaddr:&[u8],
    ) -> Result<(), String> {
        unsafe {
            match falcon1024_verify(
                data.as_ptr(),
                data.len() as i32,
                signature.as_ptr(),
                rawaddr.as_ptr(),
            ) {
                0 => Ok(()),
                -1 => Err("falcon1024 signature verification failed".to_owned()),
                _ => todo!(),
            }
        }
    }
    pub fn verify_dilithium3_sig(
        signature: &[u8],
        data: &[u8],
        rawaddr:&[u8],
    ) -> Result<(), String> {
        unsafe {
            match dilithium3_crypto_sign_verify(
                signature.as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                rawaddr.as_ptr(),
            ) {
                0 => Ok(()),
                -1 => Err("dilithium3 signature verification failed".to_owned()),
                _ => todo!(),
            }
        }
    }

    pub fn verify_dilithium5_sig(
        signature: &[u8],
        data: &[u8],
        rawaddr:&[u8],
    ) -> Result<(), String> {
        unsafe {
            match dilithium5_crypto_sign_verify(
                signature.as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                rawaddr.as_ptr(),
            ) {
                0 => Ok(()),
                1 => Err("dilithium5 signature verification failed".to_owned()),
                _ => todo!(),
            }
        }
    }
    // / Aggregates and verifies bls signatures collectively.
    pub fn verify_bls_aggregate(
        data: &[&[u8]],
        pub_keys: &[&[u8]],
        aggregate_sig: &Signature,
    ) -> bool {
        // If the number of public keys and data does not match, then return false
        if data.len() != pub_keys.len() {
            return false;
        }
        if data.is_empty() {
            return true;
        }

        let sig = match BlsSignature::from_bytes(aggregate_sig.bytes()) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let pk_map_results: Result<Vec<_>, _> =
            pub_keys.iter().map(|x| BlsPubKey::from_bytes(x)).collect();

        let pks = match pk_map_results {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Does the aggregate verification
        verify_messages(&sig, data, &pks[..])
    }

    /// Return the public key used for signing a message given it's signing bytes hash and signature.
    pub fn recover_secp_public_key(
        hash: &[u8; SECP_SIG_MESSAGE_HASH_SIZE],
        signature: &[u8; SECP_SIG_LEN],
    ) -> Result<PublicKey, Error> {
        // generate types to recover key from
        let rec_id = RecoveryId::parse(signature[64])?;
        let message = Message::parse(hash);

        // Signature value without recovery byte
        let mut s = [0u8; 64];
        s.clone_from_slice(signature[..64].as_ref());

        // generate Signature
        let sig = EcsdaSignature::parse_standard(&s)?;
        Ok(recover(&message, &sig, &rec_id)?)
    }

    /// Return Address for a message given it's signing bytes hash and signature.
    pub fn ecrecover(hash: &[u8; 32], signature: &[u8; SECP_SIG_LEN]) -> Result<Address, Error> {
        // recover public key from a message hash and secp signature.
        let key = recover_secp_public_key(hash, signature)?;
        let ret = key.serialize();
        let addr = Address::new_secp256k1(&ret)?;
        Ok(addr)
    }

    impl From<SecpError> for Error {
        fn from(err: SecpError) -> Error {
            match err {
                SecpError::InvalidRecoveryId => Error::InvalidRecovery(format!("{:?}", err)),
                _ => Error::SigningError(format!("{:?}", err)),
            }
        }
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use bls_signatures::{PrivateKey, Serialize, Signature as BlsSignature};
    use libsecp256k1::{sign, Message, PublicKey, SecretKey};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::ops::recover_secp_public_key;
    use super::*;
    use crate::crypto::signature::ops::{ecrecover, verify_bls_aggregate};
    use crate::Address;

    #[test]
    fn bls_agg_verify() {
        // The number of signatures in aggregate
        let num_sigs = 10;
        let message_length = num_sigs * 64;

        let rng = &mut ChaCha8Rng::seed_from_u64(11);

        let msg = (0..message_length).map(|_| rng.gen()).collect::<Vec<u8>>();
        let data: Vec<&[u8]> = (0..num_sigs).map(|x| &msg[x * 64..(x + 1) * 64]).collect();

        let private_keys: Vec<PrivateKey> =
            (0..num_sigs).map(|_| PrivateKey::generate(rng)).collect();
        let public_keys: Vec<_> = private_keys
            .iter()
            .map(|x| x.public_key().as_bytes())
            .collect();

        let signatures: Vec<BlsSignature> = (0..num_sigs)
            .map(|x| private_keys[x].sign(data[x]))
            .collect();

        let public_keys_slice: Vec<&[u8]> = public_keys.iter().map(|x| &**x).collect();

        let calculated_bls_agg =
            Signature::new_bls(bls_signatures::aggregate(&signatures).unwrap().as_bytes());
        assert!(verify_bls_aggregate(
            &data,
            &public_keys_slice,
            &calculated_bls_agg
        ),);
    }

    #[test]
    fn recover_pubkey() {
        let rng = &mut ChaCha8Rng::seed_from_u64(8);

        let privkey = SecretKey::random(rng);
        let pubkey = PublicKey::from_secret_key(&privkey);

        let hash: [u8; 32] = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(&[42, 43])
            .finalize()
            .as_bytes()
            .try_into()
            .expect("fixed array size");

        // Generate signature
        let (sig, recovery_id) = sign(&Message::parse(&hash), &privkey);
        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&sig.serialize());
        signature[64] = recovery_id.serialize();

        assert_eq!(pubkey, recover_secp_public_key(&hash, &signature).unwrap());
    }

    #[test]
    fn secp_ecrecover() {
        let rng = &mut ChaCha8Rng::seed_from_u64(8);

        let priv_key = SecretKey::random(rng);
        let pub_key = PublicKey::from_secret_key(&priv_key);
        let secp_addr = Address::new_secp256k1(&pub_key.serialize()).unwrap();

        let hash: [u8; 32] = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(&[8, 8])
            .finalize()
            .as_bytes()
            .try_into()
            .expect("fixed array size");

        let msg = Message::parse(&hash);

        // Generate signature
        let (sig, recovery_id) = sign(&msg, &priv_key);
        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&sig.serialize());
        signature[64] = recovery_id.serialize();

        assert_eq!(ecrecover(&hash, &signature).unwrap(), secp_addr);
    }
}

/// Crypto error
#[derive(Debug, PartialEq, Eq, Error)]
pub enum Error {
    /// Failed to produce a signature
    #[error("Failed to sign data {0}")]
    SigningError(String),
    /// Unable to perform ecrecover with the given params
    #[error("Could not recover public key from signature: {0}")]
    InvalidRecovery(String),
    /// Provided public key is not understood
    #[error("Invalid generated pub key to create address: {0}")]
    InvalidPubKey(#[from] AddressError),
}

impl From<Box<dyn error::Error>> for Error {
    fn from(err: Box<dyn error::Error>) -> Error {
        // Pass error encountered in signer trait as module error type
        Error::SigningError(err.to_string())
    }
}

impl From<EncodingError> for Error {
    fn from(err: EncodingError) -> Error {
        // Pass error encountered in signer trait as module error type
        Error::SigningError(err.to_string())
    }
}
