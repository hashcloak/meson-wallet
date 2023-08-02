use crate::bls::FIELD_ORDER;
use ark_bn254::{Fq, G1Affine};
use ark_ec::CurveGroup;
use ark_ff::fields::Field;
use ethers::core::k256::sha2::{Digest, Sha256};
use num_bigint::BigUint;

pub fn hash_to_point(msg: &[u8], domain: &[u8]) -> G1Affine {
    let e = hash_to_field(domain, msg, 2);
    let p0 = map_to_point(e[0]);
    let p1 = map_to_point(e[1]);
    let p = p0 + p1;
    p.into_affine()
}

pub fn map_to_point(mut x: Fq) -> G1Affine {
    let field_order = BigUint::parse_bytes(FIELD_ORDER, 16).unwrap();
    let f_o = Fq::from(field_order.clone());
    let z0 = Fq::from(
        BigUint::parse_bytes(
            b"0000000000000000b3c4d79d41a91759a9e4c7e359b6b89eaec68e62effffffd",
            16,
        )
        .unwrap(),
    );
    let z1 = Fq::from(
        BigUint::parse_bytes(
            b"000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe",
            16,
        )
        .unwrap(),
    );
    let decision = x.legendre().is_qr();
    let a0: Fq = (x * x) + Fq::from(4);
    let mut a1: Fq = x * z0;

    let mut a2: Fq = a1 * a0;
    a2 = a2.inverse().unwrap();
    a1 = a1 * a1 * a2;

    //x1
    a1 = x * a1;
    x = z1 + (f_o - a1);
    //check curve
    a1 = (x * x * x) + Fq::from(3);
    if a1.legendre().is_qr() {
        a1 = a1.sqrt().unwrap();
        if !decision {
            a1 = f_o - a1;
        }
        return G1Affine::new(x, a1);
    }

    //x2
    x = f_o - (x + Fq::from(1));
    //check curve
    a1 = (x * x * x) + Fq::from(3);
    if a1.legendre().is_qr() {
        a1 = a1.sqrt().unwrap();
        if !decision {
            a1 = f_o - a1;
        }
        return G1Affine::new(x, a1);
    }

    //x3
    x = a0 * a0;
    x = (x * x * a2 * a2) + Fq::from(1);
    //must be on curve
    a1 = (x * x * x) + Fq::from(3);
    //let (found, mut a1) = perfect_sqrt(a1);
    a1 = a1.sqrt().expect("BLS: bad ft mapping implementation");
    if !decision {
        a1 = f_o - a1;
    }

    G1Affine::new(x, a1)
}

pub fn hash_to_field(domain: &[u8], msg: &[u8], count: usize) -> Vec<Fq> {
    let u = 48;
    let msg = expand_msg(domain, msg, count * u);
    let mut els: Vec<Fq> = Vec::new();
    let field_order = BigUint::parse_bytes(FIELD_ORDER, 16).unwrap();
    for i in 0..count {
        let el = Fq::from(BigUint::from_bytes_be(&msg[i * u..(i + 1) * u]) % &field_order);
        els.push(el);
    }

    els
}

pub fn expand_msg(domain: &[u8], msg: &[u8], out_len: usize) -> Vec<u8> {
    if domain.len() > 32 {
        panic!("Expect 32 bytes but got {}", domain.len());
    }
    let mut out: Vec<u8> = vec![0; out_len];

    let len0 = 64 + msg.len() + 2 + 1 + domain.len() + 1;
    let mut in0: Vec<u8> = vec![0; len0];
    // zero pad
    let mut off = 64;
    //msg
    for i in msg {
        in0[off] = *i;
        off += 1;
    }
    //l_i_b_str //checked
    in0[off] = (out_len >> 8) as u8;
    in0[off + 1] = out_len as u8;
    off += 2;
    //I2OSP(0, 1)
    in0[off] = 0;
    off += 1;
    //DST_prime
    for i in domain {
        in0[off] = *i;
        off += 1;
    }
    in0[off] = domain.len() as u8;

    let b0_hash = Sha256::new().chain_update(&in0).finalize();
    let b0: &[u8] = b0_hash.as_slice();

    let len1 = 32 + 1 + domain.len() + 1;
    let mut in1: Vec<u8> = vec![0; len1];
    //b0
    let mut off = 0;
    for i in b0 {
        in1[off] = *i;
        off += 1;
    }
    // I2OSP(1, 1)
    in1[off] = 1;
    off += 1;
    //DST_prime
    for i in domain {
        in1[off] = *i;
        off += 1;
    }
    in1[off] = domain.len() as u8;

    let b1_hash = Sha256::new().chain_update(&in1).finalize();
    let b1: &[u8] = b1_hash.as_slice();

    // b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime);
    let ell = (out_len + 32 - 1) / 32;
    let mut bi = b1.to_vec();

    for i in 1..ell {
        let mut ini: Vec<u8> = vec![0; 32 + 1 + domain.len() + 1];
        let mut tmp: Vec<u8> = vec![0; 32];
        for i in 0..32 {
            tmp[i] = b0[i] ^ bi[i];
        }

        let mut off = 0;
        for i in tmp {
            ini[off] = i;
            off += 1;
        }
        ini[off] = 1 + i as u8;
        off += 1;
        for i in domain {
            ini[off] = *i;
            off += 1;
        }
        ini[off] = domain.len() as u8;

        let mut out_off: usize = 32 * (i - 1);
        for i in &bi {
            out[out_off] = *i;
            out_off += 1;
        }
        let bi_hash = Sha256::new().chain_update(&ini).finalize();
        bi = bi_hash.as_slice().to_vec();
    }

    let mut out_off = 32 * (ell - 1);
    for i in &bi {
        out[out_off] = *i;
        out_off += 1;
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;
    use sha3::Keccak256;
    #[test]
    pub fn test_expand_msg() {
        let b = Keccak256::new()
            .chain_update(b"eip4337.bls.domain")
            .finalize();
        let domain = b.as_slice();
        let msg = b"hellomieregsegstg";
        let r = expand_msg(domain, msg, 96);
        let t = vec![
            209u8, 32, 12, 59, 189, 101, 47, 22, 104, 213, 14, 56, 109, 87, 102, 48, 130, 90, 44,
            165, 117, 155, 104, 86, 251, 181, 250, 214, 234, 138, 204, 200, 131, 29, 157, 149, 1,
            128, 214, 204, 189, 31, 142, 184, 169, 75, 144, 96, 91, 146, 130, 229, 127, 14, 174,
            147, 63, 4, 227, 85, 31, 93, 218, 131, 197, 163, 34, 110, 13, 21, 42, 93, 7, 49, 128,
            44, 218, 246, 26, 168, 113, 163, 91, 198, 183, 194, 30, 76, 187, 69, 38, 216, 224, 37,
            160, 201,
        ];
        assert_eq!(r, t);
    }

    #[test]
    pub fn test_hash_to_field() {
        let b = Keccak256::new()
            .chain_update(b"eip4337.bls.domain")
            .finalize();
        let domain = b.as_slice();
        let msg = b"hellomieregsegstg";
        let r = hash_to_field(domain, msg, 2);
        let a1 = Fq::from(
            BigUint::parse_bytes(
                b"2b6c53c14a0dd94069c62918f215b55c2e2edd8e50ce0cc65e84bbc7720d56ba",
                16,
            )
            .unwrap(),
        );
        let a2 = Fq::from(
            BigUint::parse_bytes(
                b"1a1cf62f5651249ebecc8bebe979deb14ee7e06c05346b8d1a35b46791181eff",
                16,
            )
            .unwrap(),
        );
        assert_eq!(r[0], a1);
        assert_eq!(r[1], a2);
    }

    #[test]
    pub fn test_map_to_point() {
        let x1d = Fq::from(
            BigUint::parse_bytes(
                b"19595883446956508640215561788427405093248495813409234560436072835851240195455",
                10,
            )
            .unwrap(),
        );
        let x2d = Fq::from(
            BigUint::parse_bytes(
                b"18557991306220439781819603370163643464331283264676018919964060588682001706577",
                10,
            )
            .unwrap(),
        );
        let x3d = Fq::from(
            BigUint::parse_bytes(
                b"14633659353172189455729416056299012672811545913354219639207847301181504911013",
                10,
            )
            .unwrap(),
        );
        let x1nd = Fq::from(
            BigUint::parse_bytes(
                b"3188294944378234928932442675223335285430769073789785767883605143923818635513",
                10,
            )
            .unwrap(),
        );
        let x2nd = Fq::from(
            BigUint::parse_bytes(
                b"12341665609927205934528824982372185517010443167622116483577362176295910955250",
                10,
            )
            .unwrap(),
        );
        let x3nd = Fq::from(
            BigUint::parse_bytes(
                b"13618704505371309196145024835374411080024301287134654018903021974149854165834",
                10,
            )
            .unwrap(),
        );
        let r_x1d = map_to_point(x1d);
        let r_x2d = map_to_point(x2d);
        let r_x3d = map_to_point(x3d);
        let r_x1nd = map_to_point(x1nd);
        let r_x2nd = map_to_point(x2nd);
        let r_x3nd = map_to_point(x3nd);
        //test x1,decision=true
        assert_eq!(
            r_x1d,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"15151959344839800291108265089100216839146994852731104594031103855526518246717", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"3822030178848602710345671557748598165517213599016632539149495792513388035218", 10).unwrap())
            )
        );
        //test x2,decision=true
        assert_eq!(
            r_x2d,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"8075823556906057148349540751283203034939997540190829843051288279223063560500", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"706788986628130975454770585617555180331833936527535177564602529971400576122", 10).unwrap())
            )
        );
        //test x3,decision=true
        assert_eq!(
            r_x3d,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"6342895734690167420960869626906234004531469743086773157141026091677087543656", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"13571181939650287943898175741946799068268783316292952998729411109760694949933", 10).unwrap())
            )
        );
        //test x1,decision=false
        assert_eq!(
            r_x1nd,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"978925069223850629257676550816465415226059805124729863397388353544738906678", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"6424509484640449199116768710240400474207275262413926903297856179407292792409", 10).unwrap())
            )
        );
        //test x2,decision=false
        assert_eq!(
            r_x2nd,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"18400130359225322742225254599965226173782403894826135427315613521341082286682", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"20761139360730650546134315363426234803497079473571931333002775723551538596980", 10).unwrap())
            )
        );
        //test x3,decision=false
        assert_eq!(
            r_x3nd,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"7770710597554942884696310424183391835715995342615296985049868123637764828958", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"4656798052779298136963917077387622236113867604391208823406133393684648990847", 10).unwrap())
            )
        );
    }

    #[test]
    pub fn test_hash_to_point() {
        let domain = Keccak256::new()
            .chain_update(b"eip4337.bls.domain")
            .finalize();
        let msg = b"hellomieriwobgoejg";
        let a = hash_to_point(msg, &domain);
        assert_eq!(
            a,
            G1Affine::new(
                Fq::from(BigUint::parse_bytes(b"11997178017081198221716459716780604847499907722793809227088632804038703110238", 10).unwrap()),
                Fq::from(BigUint::parse_bytes(b"21036839850554353652125067833375828907719122794857623966443949244034356537794", 10).unwrap())
            )
        );
    }
}
