#![allow(dead_code)]
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::{ProvingKey, VerifyingKey};
use num_bigint::BigUint;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;
// type GrothBn = Groth16<Bn254>;

// Parse circom withdraw_proving_key.json and withdraw_verification_key.json to arkwork's key
// The parser is still under development and is currently unused

pub fn parse_proving_json(proving_path: &Path, verify_path: &Path) -> ProvingKey<Bn254> {
    let file = File::open(proving_path).unwrap();
    let reader = BufReader::new(file);
    let v: Value = serde_json::from_reader(reader).unwrap();
    let a_query = parse_g1_vec(v["A"].as_array().unwrap());
    let b_g1_query = parse_g1_vec(v["B1"].as_array().unwrap());
    let l_query = parse_g1_vec(&v["C"].as_array().unwrap()[7..]);
    let b_g2_query = parse_g2_vec(&v["B2"].as_array().unwrap());
    let h_query = parse_g1_vec(&v["hExps"].as_array().unwrap());
    let delta_g1 = parse_g1(&v["vk_delta_1"].as_array().unwrap());
    let beta_g1 = parse_g1(&v["vk_beta_1"].as_array().unwrap());
    let vk = parse_verify_json(verify_path);
    ProvingKey {
        vk,
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
    }
}

pub fn parse_verify_json(path: &Path) -> VerifyingKey<Bn254> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    let v: Value = serde_json::from_reader(reader).unwrap();
    let alpha_g1 = parse_g1(&v["vk_alfa_1"].as_array().unwrap());
    let beta_g2 = parse_g2(&v["vk_beta_2"].as_array().unwrap());
    let gamma_g2 = parse_g2(&v["vk_gamma_2"].as_array().unwrap());
    let delta_g2 = parse_g2(&v["vk_delta_2"].as_array().unwrap());
    let gamma_abc_g1 = parse_g1_vec(&v["IC"].as_array().unwrap());
    VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

pub fn parse_g1(i: &[Value]) -> G1Affine {
    let x = BigUint::from_str(i[0].as_str().unwrap()).unwrap();
    let y = BigUint::from_str(i[1].as_str().unwrap()).unwrap();
    let g1_a;
    if i[2].as_str().unwrap() == "0" {
        g1_a = G1Affine::identity();
    } else {
        g1_a = G1Affine::new(Fq::from(x), Fq::from(y));
    }
    g1_a
}

pub fn parse_g1_vec(a: &[Value]) -> Vec<G1Affine> {
    let mut vec_g1 = Vec::<G1Affine>::new();
    for i in a {
        let g1_a = parse_g1(i.as_array().unwrap());
        vec_g1.push(g1_a);
    }
    vec_g1
}

pub fn parse_g2(i: &[Value]) -> G2Affine {
    let x_c0 = BigUint::from_str(i[0][0].as_str().unwrap()).unwrap();
    let x_c1 = BigUint::from_str(i[0][1].as_str().unwrap()).unwrap();
    let y_c0 = BigUint::from_str(i[1][0].as_str().unwrap()).unwrap();
    let y_c1 = BigUint::from_str(i[1][1].as_str().unwrap()).unwrap();
    let x = Fq2::new(Fq::from(x_c0), Fq::from(x_c1));
    let y = Fq2::new(Fq::from(y_c0), Fq::from(y_c1));
    let g2_a;
    if i[2][0].as_str().unwrap() == "0" {
        g2_a = G2Affine::identity();
    } else {
        g2_a = G2Affine::new(x, y);
    }
    g2_a
}

pub fn parse_g2_vec(b: &[Value]) -> Vec<G2Affine> {
    let mut vec_g2 = Vec::<G2Affine>::new();
    for i in b {
        let g2_a = parse_g2(i.as_array().unwrap());
        vec_g2.push(g2_a);
    }
    vec_g2
}

#[cfg(test)]

mod tests {
    use ark_serialize::CanonicalSerialize;

    use super::*;
    use std::fs;

    #[test]
    pub fn test_parse_key() {
        let p = Path::new("src/circuits/withdraw_proving_key.json");
        let v = Path::new("src/circuits/withdraw_verification_key.json");
        let pk = parse_proving_json(p, v);
        let mut compressed_bytes = Vec::new();
        pk.serialize_compressed(&mut compressed_bytes).unwrap();
        fs::write("src/circuits/ProvingKeyTest", compressed_bytes).expect("Unable to write file");
    }
}
