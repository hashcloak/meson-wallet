use babyjubjub_rs::{Fr, Point};
use bitvec::{macros::internal::funty::Fundamental, prelude::*};
use blake_hash::{Blake256, Digest};
use ff_ce::{self, PrimeField};
use num_bigint::BigInt;
const GENPOINT_PREFIX: &str = "PedersenGenerator";
const WINDOW_SIZE: u128 = 4;
const N_WINDOW_PER_SEGMENT: u128 = 50;

pub fn pedersen_hash<T: AsRef<[u8]>>(msg: T) -> [u8; 32] {
    //sub_order = order >> 3
    let sub_order: BigInt = &BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
    .unwrap()
        >> 3;
    let bits_per_segment = WINDOW_SIZE * N_WINDOW_PER_SEGMENT;
    let bits: BitVec<u8, Lsb0> = BitVec::from_slice(msg.as_ref());
    let n_segments = ((bits.len().as_u128() - 1) / bits_per_segment) + 1;
    let mut acc_p = Point {
        x: Fr::from_str("0").unwrap(),
        y: Fr::from_str("1").unwrap(),
    };
    let mut bases = Vec::<Point>::new();
    for s in 0..n_segments {
        let n_windows;
        //calculate number of windows in a segment in case of last segment
        if s == n_segments - 1 {
            n_windows = (((bits.len().as_u128() - (n_segments - 1) * bits_per_segment) - 1)
                / WINDOW_SIZE)
                + 1;
        } else {
            n_windows = N_WINDOW_PER_SEGMENT;
        }
        let mut escalar: BigInt = 0i32.into();
        let mut exp: BigInt = 1i32.into();

        for w in 0..n_windows {
            //bit offset in msg
            let mut o = s * bits_per_segment + w * WINDOW_SIZE;
            let mut acc: BigInt = 1i32.into();
            //b_0 b_1 b_2 in a four-bit-window (acc = 1+b_0+2b_1+4b_2)
            let mut b = 0u128;
            while b < WINDOW_SIZE - 1 && o < bits.len().as_u128() {
                if bits[o.as_usize()] {
                    let to_add: BigInt = (1i64 << b).into();
                    acc = acc + (&to_add);
                }
                b += 1;
                o += 1;
            }
            //b_3 if 1 then -acc; if 0 then +acc (opposite to the paper)
            if o < bits.len().as_u128() {
                if bits[o.as_usize()] {
                    acc = -acc;
                }
            }

            escalar = escalar + (acc * &exp);
            exp = exp << (WINDOW_SIZE + 1);
        }
        if escalar < BigInt::from(0) {
            escalar = &sub_order + &escalar;
        }
        let base_point = get_base_point(s.as_usize(), &mut bases);
        let p_to_add = base_point.mul_scalar(&escalar);
        acc_p = acc_p.projective().add(&(p_to_add.projective())).affine();
    }
    return acc_p.compress();
}

fn get_base_point(point_idx: usize, bases: &mut Vec<Point>) -> Point {
    if point_idx < bases.len() {
        return bases[point_idx].clone();
    }
    let mut try_idx = 0;
    loop {
        let s = format!(
            "{}_{}_{}",
            GENPOINT_PREFIX,
            pad_left_zeros(&point_idx.to_string(), 32),
            pad_left_zeros(&try_idx.to_string(), 32)
        );
        let b_hash = Blake256::new();
        let mut h = b_hash.chain(&s.as_bytes()).finalize();
        h[31] = h[31] & 0xBF;
        match babyjubjub_rs::decompress_point(h.as_slice().try_into().unwrap()) {
            Ok(point) => {
                let p8 = point.mul_scalar(&8i32.into());
                //probably need to check if p8 is in subgroup like in cricomlib
                bases.push(p8.clone());
                return p8;
            }
            Err(_) => try_idx += 1,
        }
    }
}

fn pad_left_zeros(idx_str: &str, n: u64) -> String {
    let mut result = idx_str.to_string();
    while result.len() < n.as_usize() {
        result = "0".to_string() + &result;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_zeros() {
        let idx = "10654981";
        let res = pad_left_zeros(idx, 32);
        assert_eq!(&res, "00000000000000000000000010654981");
    }

    #[test]
    fn test_base_point() {
        let mut bases = Vec::<Point>::new();
        let p = get_base_point(10, &mut bases);

        let req = Point {
            x: Fr::from_str(
                "16246587114701919230396141881596483298016809673932703125119295166936827150109",
            )
            .unwrap(),
            y: Fr::from_str(
                "2008259283001433748666303325888612438000671916354550248296035439458960131795",
            )
            .unwrap(),
        };
        assert_eq!(p.x, req.x);
        assert_eq!(p.y, req.y);
    }

    #[test]
    fn test_hash() {
        let msg = "This is a simple rust pedersen-hash implementation based on circom's js library";
        let res = pedersen_hash(msg);
        let req: [u8; 32] = [
            0xb5, 0x4e, 0xa6, 0x17, 0x1c, 0x39, 0x26, 0xd9, 0x38, 0x7e, 0x21, 0x5f, 0x2b, 0xcd,
            0xff, 0x24, 0x16, 0x61, 0xd6, 0xf5, 0x69, 0x9c, 0xd4, 0xdb, 0x8e, 0xff, 0xc0, 0xdd,
            0x48, 0xd9, 0x08, 0x07,
        ];
        assert_eq!(res, req);
    }
}
