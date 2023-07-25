use ethers::core::k256::sha2::{Digest, Sha256};

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
    use sha3::{Digest, Keccak256};
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
}
