use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{fields::Field, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ethers::core::k256::sha2::{Digest, Sha256};
use ethers::core::types::U256;
use hash_to_point::hash_to_point;
use num_bigint::BigUint;
use sha3::Keccak256;
pub mod hash_to_point;
pub mod multi_sig;

//order of Fq
pub const FIELD_ORDER: &[u8] = b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
pub const DOMAIN: &[u8] = b"eip4337.bls.domain";
pub struct PrivateKey(Fr);

pub struct PublicKey(G2Affine);

impl PrivateKey {
    pub fn new<R: rand::Rng>(rng: &mut R) -> Self {
        let sk = Fr::rand(rng);
        PrivateKey(sk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        BigUint::from(self.0).to_bytes_be()
    }

    pub fn derive_public_key(&self) -> PublicKey {
        PublicKey((G2Affine::generator() * (self.0)).into())
    }
}

impl PublicKey {
    pub fn from_compressed(bytes: &[u8]) -> Self {
        let g2 = G2Affine::deserialize_compressed(bytes).unwrap();
        PublicKey(g2)
    }

    pub fn from_uncompressed(bytes: &[u8]) -> Self {
        let g2 = G2Affine::deserialize_uncompressed(bytes).unwrap();
        PublicKey(g2)
    }

    pub fn to_compressed(&self) -> Vec<u8> {
        let mut compressed_bytes = Vec::<u8>::new();
        self.0.serialize_compressed(&mut compressed_bytes).unwrap();
        compressed_bytes
    }

    pub fn to_uncompressed(&self) -> Vec<u8> {
        let mut uncompressed_bytes = Vec::<u8>::new();
        self.0
            .serialize_uncompressed(&mut uncompressed_bytes)
            .unwrap();
        uncompressed_bytes
    }

    //to solidity uint256[4], different from to_uncompressed
    pub fn to_solidity_pk(&self) -> [U256; 4] {
        let x_c0 = U256::from(BigUint::from(self.0.x.c0).to_bytes_be().as_slice());
        let x_c1 = U256::from(BigUint::from(self.0.x.c1).to_bytes_be().as_slice());
        let y_c0 = U256::from(BigUint::from(self.0.y.c0).to_bytes_be().as_slice());
        let y_c1 = U256::from(BigUint::from(self.0.y.c1).to_bytes_be().as_slice());
        [x_c0, x_c1, y_c0, y_c1]
    }
}

pub fn sign(sk: &PrivateKey, msg: &[u8]) -> Vec<u8> {
    let domain = Keccak256::new().chain_update(DOMAIN).finalize();
    let hash_point = hash_to_point(msg, &domain);

    let signature = hash_point * sk.0;
    to_uncompressed_g1(&signature.into_affine())
}

pub fn verify(pk: &PublicKey, msg: &[u8], signature: &[u8]) -> bool {
    let domain = Keccak256::new().chain_update(DOMAIN).finalize();
    let msg_point = hash_to_point(msg, &domain);
    let sig_point = G1Affine::new(
        BigUint::from_bytes_be(&signature[..32]).into(),
        BigUint::from_bytes_be(&signature[32..]).into(),
    );
    let e1 = Bn254::pairing(sig_point, G2Affine::generator());
    let e2 = Bn254::pairing(msg_point, pk.0);
    e1 == e2
}

//Returns G1 Affine in uncompressed bytes
pub fn to_uncompressed_g1(point: &G1Affine) -> Vec<u8> {
    let x = big_endian_pad_to_u256(BigUint::from(point.x).to_bytes_be());
    let y = big_endian_pad_to_u256(BigUint::from(point.y).to_bytes_be());
    [x, y].concat()
}

//Sha256 hash to Fr
fn hash_to_fr(msg: &[u8]) -> Fr {
    let sha_msg = Sha256::new().chain_update(msg).finalize();
    Fr::from(BigUint::from_bytes_be(&sha_msg))
}

fn big_endian_pad_to_u256(bytes: Vec<u8>) -> Vec<u8> {
    let diff = 32 - bytes.len();
    if diff != 0 {
        let bytes = [vec![0u8; diff], bytes].concat();
        return bytes;
    }
    bytes
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn test_sig_veri() {
        let mut rng = rand::thread_rng();
        let sk = PrivateKey::new(&mut rng);
        let pk = sk.derive_public_key();

        let sk2 = PrivateKey::new(&mut rng);
        let pk2 = sk2.derive_public_key();
        let msg = b"hellothere";

        let sig = sign(&sk, msg);
        let res = verify(&pk, msg, &sig);
        assert!(res);

        let res_f = verify(&pk2, msg, &sig);
        assert!(!res_f);
    }

    #[test]
    pub fn test_ser() {
        let mut rng = rand::thread_rng();
        let sk = PrivateKey::new(&mut rng);
        let pk = sk.derive_public_key();
        let msg = b"hellomieriwobgoejg";
        let sig = sign(&sk, msg);

        let res = verify(&pk, msg, &sig);
        assert!(res);

        let uc_pk = pk.to_uncompressed();
        let pk2 = PublicKey::from_uncompressed(&uc_pk);
        let res2 = verify(&pk2, msg, &sig);
        assert!(res2);
        assert!(pk.0 == pk2.0);

        let c_pk = pk.to_compressed();
        let pk3 = PublicKey::from_compressed(&c_pk);
        let res3 = verify(&pk3, msg, &sig);
        assert!(res3);
        assert!(pk.0 == pk3.0);
    }
}
