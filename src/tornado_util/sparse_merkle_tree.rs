use ff_ce::{Field, PrimeField};
use mimc_sponge_rs::{Fr, MimcSponge};
const DEFAULT_ZERO: &str =
    "21663839004416932945382355908790599225266501822907911457504978515578255421292";

#[derive(Debug)]
pub struct MerkleTree<T: PrimeField> {
    pub levels: usize,
    pub capacity: u128,
    pub zero_element: String,
    pub zeros: Vec<T>,
    pub layers: Vec<Vec<T>>,
    pub hash_fn: fn(T, T) -> T,
}

impl<T: PrimeField> MerkleTree<T> {
    pub fn new(
        levels: usize,
        zero_element: Option<String>,
        hash_fn: fn(T, T) -> T,
        elements: Option<Vec<T>>,
    ) -> MerkleTree<T> {
        let capacity = 2u128.pow(u32::try_from(levels).unwrap());
        let zero_element = match zero_element {
            Some(s) => s, //todo: check sanity
            None => DEFAULT_ZERO.into(),
        };
        let mut zeros = Vec::<T>::new();
        let mut layers = Vec::<Vec<T>>::new();
        zeros.push(T::from_str(&zero_element).unwrap());
        layers.push(Vec::<T>::new()); //to initiate first layer
        for i in 1..=levels {
            zeros.push(hash_fn(zeros[i - 1], zeros[i - 1]));
            layers.push(Vec::<T>::new()); //to initiate each layer
        }
        match elements {
            Some(v) => {
                if v.len() > capacity.try_into().unwrap() {
                    panic!("Tree is full");
                };
                layers[0] = v
            }
            None => (),
        }

        let mut mk = MerkleTree::<T> {
            levels,
            capacity,
            zero_element,
            zeros,
            layers,
            hash_fn,
        };

        mk.rebuild();

        mk
    }

    fn rebuild(&mut self) {
        for level in 1..=self.levels {
            let lim = (self.layers[level - 1].len() + 1) / 2; //ceil(layers[level-1].len()/2)
            for i in 0..lim {
                let left = self.layers[level - 1][i * 2];
                let right = if i * 2 + 1 < self.layers[level - 1].len() {
                    self.layers[level - 1][i * 2 + 1]
                } else {
                    self.zeros[level - 1]
                };
                self.layers[level].push((self.hash_fn)(left, right));
            }
        }
    }

    pub fn root(&self) -> T {
        if self.layers[self.levels].len() == 0 {
            self.zeros[self.levels]
        } else {
            self.layers[self.levels][0]
        }
    }

    pub fn path(&self, mut index: u128) -> (Vec<T>, Vec<u128>) {
        if index >= self.layers[0].len().try_into().unwrap() {
            panic!("Index out of bound");
        }
        let mut pathElements = Vec::<T>::new();
        let mut pathIndices = Vec::<u128>::new();
        for level in 0..self.levels {
            pathIndices.push(index % 2);
            let element = if index ^ 1 < self.layers[level].len().try_into().unwrap() {
                self.layers[level][usize::try_from(index ^ 1).unwrap()]
            } else {
                self.zeros[level]
            };

            pathElements.push(element);

            index >>= 1;
        }
        (pathElements, pathIndices)
    }

    pub fn update(&mut self, mut index: usize, element: T) {
        if index >= self.layers[0].len() || index >= self.capacity.try_into().unwrap() {
            panic!("Index out of bound");
        }
        self.layers[0][index] = element;
        for level in 1..=self.levels {
            index >>= 1;
            let left = self.layers[level - 1][index * 2];
            let right = if index * 2 + 1 < self.layers[level - 1].len() {
                self.layers[level - 1][index * 2 + 1]
            } else {
                self.zeros[level - 1]
            };
            if index == self.layers[level].len() {
                self.layers[level].push((self.hash_fn)(left, right));
            } else {
                self.layers[level][index] = (self.hash_fn)(left, right);
            }
        }
    }

    pub fn insert(&mut self, element: T) {
        if u128::try_from(self.layers[0].len()).unwrap() >= self.capacity {
            panic!("Tree is full");
        }
        self.layers[0].push(T::zero());
        self.update(self.layers[0].len() - 1, element)
    }

    pub fn bulkInsert(&mut self, elements: Vec<T>) {
        if u128::try_from(self.layers[0].len() + elements.len()).unwrap() >= self.capacity {
            panic!("Tree is full");
        }

        for i in 0..elements.len() - 1 {
            self.layers[0].push(elements[i]);
            let mut level = 0;
            let mut index = self.layers[0].len() - 1;
            while index % 2 == 1 {
                level += 1;
                index >>= 1;
                let left = self.layers[level - 1][index * 2];
                let right = self.layers[level - 1][index * 2 + 1];
                if index == self.layers[level].len() {
                    self.layers[level].push((self.hash_fn)(left, right));
                } else {
                    self.layers[level][index] = (self.hash_fn)(left, right);
                }
            }
        }
        self.insert(elements[elements.len() - 1]);
    }
}

pub fn default_hash(left: Fr, right: Fr) -> Fr {
    let arr = vec![left, right];
    let ms = MimcSponge::default();
    let k = Fr::zero();
    let res = ms.multi_hash(&arr, k, 1);
    return res[0];
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    pub fn test_new() {
        let elements = vec![
            Fr::from_str("100").unwrap(),
            Fr::from_str("7").unwrap(),
            Fr::from_str("3").unwrap(),
            Fr::from_str("4").unwrap(),
        ];
        let mt = MerkleTree::new(5, None, default_hash, Some(elements));
        assert_eq!(
            mt.root().to_string(),
            "Fr(0x159e1688baa5baceec83bd06ed6f0dbb1a28c612b1cf1428a4aabb6b9849450e)"
        );
        let path_str = format!("{:?}", mt.path(1));
        assert_eq!(path_str,"([Fr(0x0000000000000000000000000000000000000000000000000000000000000064), Fr(0x1476b92b5dabf861814ddb7c9155087cee756315be19b9ee7b17b161a17bdb66), Fr(0x1151949895e82ab19924de92c40a3d6f7bcb60d92b00504b8199613683f0c200), Fr(0x20121ee811489ff8d61f09fb89e313f14959a0f28bb428a20dba6b0b068b3bdb), Fr(0x0a89ca6ffa14cc462cfedb842c30ed221a50a3d6bf022a6a57dc82ab24c157c9)], [1, 0, 0, 0, 0])")
    }

    #[test]
    pub fn test_update() {
        let elements = vec![
            Fr::from_str("5").unwrap(),
            Fr::from_str("30").unwrap(),
            Fr::from_str("0").unwrap(),
            Fr::from_str("513268751230").unwrap(),
            Fr::from_str("66").unwrap(),
            Fr::from_str("68421").unwrap(),
        ];
        let mut mt = MerkleTree::new(50, None, default_hash, Some(elements));
        mt.update(2, Fr::from_str("7").unwrap());
        assert_eq!(
            mt.root().to_string(),
            "Fr(0x0db3f83751f8eac45d66b028884ec35e8d03167fec6fbd72b9a71764cc6d2ac8)"
        );
    }

    #[test]

    pub fn test_bulk_insert() {
        let elements = vec![
            Fr::from_str("6").unwrap(),
            Fr::from_str("95").unwrap(),
            Fr::from_str("10").unwrap(),
        ];
        let mut mt = MerkleTree::new(33, None, default_hash, Some(elements));
        mt.bulkInsert(vec![
            Fr::from_str("45").unwrap(),
            Fr::from_str("33").unwrap(),
            Fr::from_str("107").unwrap(),
            Fr::from_str("537869").unwrap(),
        ]);
        assert_eq!(
            mt.root().to_string(),
            "Fr(0x06506991fef3d4e9e095456e8b16b086d17b364151074b2a9d5f6f00fe314983)"
        );
    }
}
