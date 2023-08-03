use crate::bls::{hash_to_fr, hash_to_point, to_uncompressed_g1, PrivateKey, PublicKey, DOMAIN};
use ark_bn254::{Fr, G1Projective, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ethers::core::k256::sha2::Digest;
use sha3::Keccak256;

pub struct MultiSigPublicKey {
    apk: PublicKey,
    pks_concat: Vec<u8>,
}

impl MultiSigPublicKey {
    pub fn new(pks: &[&PublicKey]) -> Self {
        let mut apk = G2Projective::zero();
        let pks_concat: Vec<Vec<u8>> = pks.iter().map(|pk| pk.to_uncompressed()).collect();
        let pks_concat = pks_concat.concat();
        for pk in pks {
            let mut pk_pks = pk.to_uncompressed();
            pk_pks.extend(&pks_concat);
            let hpks_i = hash_to_fr(&pk_pks);
            apk = apk + (pk.0 * hpks_i);
        }
        MultiSigPublicKey {
            apk: PublicKey(apk.into_affine()),
            pks_concat: pks_concat,
        }
    }
}

pub fn public_key_aggregation(pks: &[PublicKey]) -> PublicKey {
    let mut apk = G2Projective::zero();
    let pks_concat: Vec<Vec<u8>> = pks.iter().map(|pk| pk.to_uncompressed()).collect();
    let pks_concat = pks_concat.concat();
    for pk in pks {
        let mut pk_pks = pk.to_uncompressed();
        pk_pks.extend(&pks_concat);
        let hpks_i = hash_to_fr(&pk_pks);
        apk = apk + (pk.0 * hpks_i);
    }
    PublicKey(apk.into_affine())
}

pub fn multi_sig_sign(
    mpk: &MultiSigPublicKey,
    sk: &PrivateKey,
    pk: &PublicKey,
    msg: &[u8],
) -> G1Projective {
    let mut pk_pks = pk.to_uncompressed();
    pk_pks.extend(&mpk.pks_concat);
    let hpks_i = hash_to_fr(&pk_pks);
    let tmp_sk: Fr = hpks_i * sk.0;

    let domain = Keccak256::new().chain_update(DOMAIN).finalize();
    let hash_point = hash_to_point(msg, &domain);
    let signature = hash_point * tmp_sk;
    signature
}

pub fn multi_sig_combine_sig(sigs: &[G1Projective]) -> Vec<u8> {
    let mut asig = G1Projective::zero();
    for sig in sigs {
        asig = asig + sig;
    }
    to_uncompressed_g1(&asig.into_affine())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bls::verify;
    #[test]
    pub fn test_multi_sig() {
        let mut rng = rand::thread_rng();
        let msg = b"hellomieriwobgoejg";
        let sk = PrivateKey::new(&mut rng);
        let pk = sk.derive_public_key();
        let sk2 = PrivateKey::new(&mut rng);
        let pk2 = sk2.derive_public_key();
        let sk3 = PrivateKey::new(&mut rng);
        let pk3 = sk3.derive_public_key();
        let pks = &[&pk, &pk2, &pk3];
        let mpk = MultiSigPublicKey::new(pks);
        let s1 = multi_sig_sign(&mpk, &sk, &pk, msg);
        let s2 = multi_sig_sign(&mpk, &sk2, &pk2, msg);
        let s3 = multi_sig_sign(&mpk, &sk3, &pk3, msg);
        let sigs = &[s1, s2, s3];
        let asig = multi_sig_combine_sig(sigs);
        let res = verify(&mpk.apk, msg, &asig);
        println!("{}", res);
    }
}