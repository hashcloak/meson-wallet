use ark_bn254::Bn254;
use ark_circom::{ethereum, CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use babyjubjub_rs::{decompress_point, Fr, Point};
use ethers::abi::{AbiEncode, Address};
use ethers::prelude::{Bytes, Filter, Middleware, Provider, U256};
use ethers::{utils, utils::hex::FromHex};
use ff_ce::{from_hex, Field, PrimeField};
use mimc_sponge_rs::Fr as mimc_fr;
use num_bigint::{BigInt, Sign};
use rand::{thread_rng, Rng, SeedableRng};
use std::str::FromStr;
use std::sync::Arc;
type GrothBn = Groth16<Bn254>;
use std::fs;

pub mod pedersen_hash;
pub mod sparse_merkle_tree;
// abigen!(Tornado, "src/ETHTornado.json");
#[derive(Debug)]
pub struct Deposit {
    pub nullifier: BigInt,
    pub secret: BigInt,
    pub preimage: Vec<u8>,
    pub commitment: Fr,
    pub commitment_hex: String,
    pub nullifier_hash: Fr,
    pub nullifier_hex: String,
}
const DEPOSIT_SIGNATURE: &str = "0xb214faa5";
const WITHDRAW_SIGNATURE: &str = "0x21a0adb6";
const TORNADO_ADDRESS: &str = "0xFfB729553fEA430AdDab48D8F9f42d5b6CA87270";
const MERKLE_LEVEL: usize = 20;
impl Deposit {
    pub fn new() -> Self {
        let mut r = thread_rng();
        // let mut r = StdRng::seed_from_u64(11);
        let nullifier_random_bytes = r.gen::<[u8; 31]>();
        let nullifier = BigInt::from_bytes_le(num_bigint::Sign::Plus, &nullifier_random_bytes);
        let secret_random_bytes: [u8; 31] = r.gen::<[u8; 31]>();
        let secret = BigInt::from_bytes_le(num_bigint::Sign::Plus, &secret_random_bytes);
        let preimage = [
            nullifier_random_bytes.as_slice(),
            secret_random_bytes.as_slice(),
        ]
        .concat();

        let commitment = decompress_point(pedersen_hash::pedersen_hash(&preimage))
            .unwrap()
            .x;
        let commitment_hex = format!("0x{}", ff_ce::to_hex(&commitment));
        let nullifier_hash =
            decompress_point(pedersen_hash::pedersen_hash(&nullifier_random_bytes))
                .unwrap()
                .x;
        let nullifier_hex = format!("0x{}", ff_ce::to_hex(&nullifier_hash));

        Deposit {
            nullifier,
            secret,
            preimage,
            commitment,
            commitment_hex,
            nullifier_hash,
            nullifier_hex,
        }
    }

    pub fn gen_deposit_tx(&self, currency: Option<String>, amount: String, net_id: u64) -> Vec<u8> {
        let currency = currency.unwrap_or("eth".into());
        let preimage_hex = utils::hex::encode(&self.preimage);
        let note_string = format!("tornado-{currency}-{amount}-{net_id}-0x{preimage_hex}");
        let value = utils::parse_ether(amount).unwrap();
        let deposit_sig = Bytes::from_str(DEPOSIT_SIGNATURE).unwrap().to_vec();
        let commitment_vec = Bytes::from_str(&self.commitment_hex).unwrap().to_vec();
        let tx_vec = [deposit_sig, commitment_vec].concat();
        println!("{}", note_string);
        tx_vec
    }

    pub async fn parse_and_withdraw(
        note: &str,
        recipient: Address,
        relayer: Option<Address>,
        fee: Option<U256>,
        refund: Option<U256>,
    ) -> Vec<u8> {
        let deposit = Self::parse_note(note);
        deposit
            .gen_withdraw_tx(recipient, relayer, fee, refund)
            .await
    }

    pub async fn gen_withdraw_tx(
        &self,
        recipient: Address,
        relayer: Option<Address>,
        fee: Option<U256>,
        refund: Option<U256>,
    ) -> Vec<u8> {
        let relayer = match relayer {
            Some(a) => a,
            None => Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
        };
        let fee = match fee {
            Some(a) => a,
            None => 0i32.into(),
        };
        let refund = match refund {
            Some(a) => a,
            None => 0i32.into(),
        };
        let (proof, root) = generate_proof(self, recipient, relayer, fee, refund).await;
        let nullifier_hash = U256::from_str(&ff_ce::to_hex(&self.nullifier_hash)).unwrap();
        let params =
            AbiEncode::encode((proof, root, nullifier_hash, recipient, relayer, fee, refund));
        let withdraw_sig = Bytes::from_str(WITHDRAW_SIGNATURE).unwrap().to_vec();
        let tx_vec = [withdraw_sig, params].concat();
        tx_vec
    }

    pub fn parse_note(note: &str) -> Deposit {
        let mut note_iter = note.split("-");
        note_iter.next();
        let currency = note_iter.next().unwrap();
        let amount = note_iter.next().unwrap();
        let net_id = note_iter.next().unwrap();
        let preimage_hex = note_iter.next().unwrap().strip_prefix("0x").unwrap();
        let preimage = <[u8; 62]>::from_hex(preimage_hex).unwrap().to_vec();
        let nullifier_random_bytes = &preimage[..31];
        let secret_random_bytes = &preimage[31..];
        let nullifier = BigInt::from_bytes_le(num_bigint::Sign::Plus, nullifier_random_bytes);
        let secret = BigInt::from_bytes_le(num_bigint::Sign::Plus, &secret_random_bytes);
        let nullifier_hash =
            decompress_point(pedersen_hash::pedersen_hash(&nullifier_random_bytes))
                .unwrap()
                .x;
        let nullifier_hex = format!("0x{}", ff_ce::to_hex(&nullifier_hash));
        let commitment = decompress_point(pedersen_hash::pedersen_hash(&preimage))
            .unwrap()
            .x;
        let commitment_hex = format!("0x{}", ff_ce::to_hex(&commitment));
        let deposit = Deposit {
            nullifier,
            secret,
            preimage,
            commitment,
            commitment_hex,
            nullifier_hash,
            nullifier_hex,
        };
        deposit
    }
}

pub async fn generate_merkle_proof(deposit: &Deposit) -> (Vec<mimc_fr>, Vec<u128>, mimc_fr) {
    //todo: fetch addr from env of cfg
    let tornado_addr: Address = TORNADO_ADDRESS.parse().unwrap();
    let rpc_url = "http://localhost:8545";
    let provider = Provider::try_from(rpc_url).unwrap();
    let client = Arc::new(provider);
    let filter = Filter::new()
        .address(tornado_addr)
        .event("Deposit(bytes32,uint32,uint256)")
        .from_block(0);
    let mut logs = client.get_logs(&filter).await.unwrap();
    logs.sort_by(|a, b| {
        U256::from_big_endian(&a.data[28..32])
            .partial_cmp(&U256::from_big_endian(&b.data[28..32]))
            .unwrap()
    });
    // println!("{}", &logs[0].topics[1]);
    let leaves: Vec<mimc_fr> = logs
        .iter()
        .map(|log| from_hex::<mimc_fr>(&utils::hex::encode(log.topics[1])).unwrap())
        .collect();
    println!("{:?}", leaves);
    let mut index = 0u128;
    for i in 0..leaves.len() {
        if format!("0x{}", ff_ce::to_hex(&leaves[i])) == deposit.commitment_hex {
            index = i.try_into().unwrap();
            break;
        }
        if i == leaves.len() {
            panic!("No commitment found");
        }
    }
    println!("{}", index);
    let tree = sparse_merkle_tree::MerkleTree::new(
        MERKLE_LEVEL,
        None,
        sparse_merkle_tree::default_hash,
        Some(leaves),
    );
    let root = tree.root();
    let (pathElements, pathIndices) = tree.path(index);
    return (pathElements, pathIndices, root);
}

pub async fn generate_proof(
    deposit: &Deposit,
    recipient: Address,
    relayer: Address,
    fee: U256,
    refund: U256,
) -> (Bytes, U256) {
    let cfg =
        CircomConfig::<Bn254>::new("src/circuits/withdraw.wasm", "src/circuits/withdraw.r1cs")
            .unwrap();
    let (path_elements, path_indices, root) = generate_merkle_proof(deposit).await;
    let mut builder = CircomBuilder::new(cfg);
    let bi_root = BigInt::from_bytes_be(
        Sign::Plus,
        &utils::hex::decode(ff_ce::to_hex(&root)).unwrap(),
    );
    let bi_nullifier_hash = BigInt::from_bytes_be(
        Sign::Plus,
        &utils::hex::decode(ff_ce::to_hex(&deposit.nullifier_hash)).unwrap(),
    );
    let bi_recipient = BigInt::from_bytes_be(Sign::Plus, recipient.as_bytes());
    let bi_relayer = BigInt::from_bytes_be(Sign::Plus, relayer.as_bytes());
    let bi_fee = BigInt::from_bytes_be(Sign::Plus, &fee.encode());
    let bi_refund = BigInt::from_bytes_be(Sign::Plus, &refund.encode());
    builder.push_input("root", bi_root.clone());
    builder.push_input("nullifierHash", bi_nullifier_hash.clone());
    builder.push_input("recipient", bi_recipient.clone());
    builder.push_input("relayer", bi_relayer.clone());
    builder.push_input("fee", bi_fee.clone());
    builder.push_input("refund", bi_refund.clone());
    builder.push_input("nullifier", deposit.nullifier.clone());
    builder.push_input("secret", deposit.secret.clone());

    for path_element in path_elements {
        let bi_path_element = BigInt::from_bytes_be(
            Sign::Plus,
            &utils::hex::decode(ff_ce::to_hex(&path_element)).unwrap(),
        );
        builder.push_input("pathElements", bi_path_element);
    }

    for path_index in path_indices {
        builder.push_input("pathIndices", path_index);
    }

    let mut rng = thread_rng();
    let compressed_bytes = fs::read("src/circuits/ProvingKey").unwrap();
    let params = ProvingKey::<Bn254>::deserialize_compressed_unchecked(&*compressed_bytes).unwrap();

    let circom = builder.build().unwrap();
    let inputs = circom.get_public_inputs().unwrap();
    let proof = GrothBn::prove(&params, circom, &mut rng).unwrap();
    let pvk = GrothBn::process_vk(&params.vk).unwrap();
    // let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
    // println!("result:{}", verified);

    let vk: ethereum::VerifyingKey = params.vk.into();

    let a = ethereum::G1::from(&proof.a);
    let a_x = a.x.encode();
    let a_y = a.y.encode();
    let b = ethereum::G2::from(&proof.b);
    let b_x_0 = b.x[1].encode();
    let b_x_1 = b.x[0].encode();
    let b_y_0 = b.y[1].encode();
    let b_y_1 = b.y[0].encode();
    let c = ethereum::G1::from(&proof.c);
    let c_x = c.x.encode();
    let c_y = c.y.encode();

    //to verify.sol input
    let proof_bytes: Bytes = [a_x, a_y, b_x_0, b_x_1, b_y_0, b_y_1, c_x, c_y]
        .concat()
        .into();

    let root_u256 = U256::from_big_endian(&bi_root.to_bytes_be().1);

    (proof_bytes, root_u256)
}

fn to_be_bytes(u64_4_in: &[u64; 4]) -> Vec<u8> {
    let mut result: [u8; 32] = [0; 32];
    let mut index = 32;
    for i in u64_4_in {
        let s = i.to_le_bytes();
        for j in s {
            index -= 1;
            result[index] = j;
        }
    }
    result.to_vec()
}

#[cfg(test)]

mod tests {
    use super::*;
    use ethers::{
        core::types::{Address, Filter, H160, H256, U256},
        providers::{Http, Middleware, Provider},
    };
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    pub fn test_deposit() {
        let d = Deposit::new();

        let tx = d.gen_deposit_tx(None, "0.1".into(), 1683880318909);
        println!("{:?}", tx);
    }

    #[tokio::test]
    pub async fn test_sign_deposit_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:8545";
        let deposit = Deposit::new();
        let tx = deposit.gen_deposit_tx(None, "0.1".into(), 1337);
        let data = "0x".to_owned() + &utils::hex::encode(tx);
        println!("{}", data);
        let provider = Provider::try_from(rpc_url).unwrap();
        let r: String = provider
            .request(
                "eth_signTransaction",
                json!([{
                    "from":"0xC776A63D28fDCCe9b2c7fb0Ad07FcEe95298bD46",
                    "to":TORNADO_ADDRESS,
                    "gas":10000000,
                    "value":100000000000000000i64,
                    "maxFeePerGas": 250000000000i64,
                    "maxPriorityFeePerGas": 250000000000i64,
                    "data": data,
                }]),
            )
            .await
            .unwrap();
        println!("{r}");
    }

    #[tokio::test]
    pub async fn test_deposit_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:8545";
        let provider = Provider::try_from(rpc_url).unwrap();
        let r: String = provider
            .request(
                "eth_sendRawTransaction",
                json!(["0x02f89b82053980853a35294400853a352944008398968094ffb729553fea430addab48d8f9f42d5b6ca8727088016345785d8a0000a4b214faa5150b3bedf67a73a81d271167a484862938a1c912c62104f4c0ab360476cb8fadc001a00bb94b11f582328146245d298650e40acd53f221447242f96d123f142f083200a0625cb43f9fa9e2d3949c1545967f71c51838bb33cb9a94f37a9ac93431ac365d"]),
            )
            .await
            .unwrap();
        println!("{r}");
    }

    #[tokio::test]
    pub async fn test_proof() {
        let rpc_url = "http://localhost:8545";
        let r = Address::from_str("0xBa0A599E2cc8f0C45FA2E7cd9Ab2F14751c8b84e").unwrap();
        let note = "tornado-eth-0.1-1337-0xf6baa0f9082cfe4df59e4829ada89cedd9b431068a81d3942d2ace2fc62b27c8fd2ae8d3d1cdaaa71005fddd7cc7bbde27378b46e6bc152fb8be040de146";
        let tx = Deposit::parse_and_withdraw(note, r, None, None, None).await;
        let data = "0x".to_owned() + &utils::hex::encode(tx);
        let provider = Provider::try_from(rpc_url).unwrap();
        let r: String = provider
            .request(
                "eth_signTransaction",
                json!([{
                    "from":"0x3Db94B4389DB32A276F81a14B47225D3A028Fe8F",
                    "to":TORNADO_ADDRESS,
                    "gas":1000000i64,
                    "value":0,
                    "maxFeePerGas": 528287720,
                    "maxPriorityFeePerGas": 0,
                    "data": data
                }]),
            )
            .await
            .unwrap();
        println!("{r}");
    }

    #[tokio::test]
    pub async fn test_withdraw_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:8545";
        let provider = Provider::try_from(rpc_url).unwrap();
        let r: String = provider
            .request(
                "eth_sendRawTransaction",
                json!(["0x02f9027382053980843b9aca00841f7d07e8830f424094ffb729553fea430addab48d8f9f42d5b6ca8727080b9020421a0adb600000000000000000000000000000000000000000000000000000000000000e01d9a72c1fba935176b8269d6756a82fff5026cc95d943a6b3bb74ade007033b90a5a23c91211e5567aa5ebb5b9ab46b1d74fcca0a79a70333e20622ea129aaa9000000000000000000000000ba0a599e2cc8f0c45fa2e7cd9ab2f14751c8b84e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001f79237b93e8ad6a69e733b99a6c1deab4257aee64e6e541237bd675562637f20cbb4263ce3381cbc4fbb65b5fe1ec10f779fc98448933032a5de1bf56b5d3b500ce9b7ed884f5b7a0a477a1e7791b83c302bdee9d5046df31733f4d97e271ff0960f3714a1034714f2af01b871ad79f705da6c4f293126a89ba2ac9ca25c1512bec55ad93b9b456d0dd44f38dc05fc618f00e04443862c47b0e644f45dd128601a77d84406d7c64ef4fa99a8e2d14a1a4b3d903c841222c068580eb52e7ed452bcd4378bd510051dca5aecd3df95d9550f551a75960b352876ba1ecc5f74f5a1e75fe2185e237bcbe723849be3429116b2c163b9d15a8e676bb8d3c34e1d44ec080a01c8287ef8c14a02efe72f2e2412c5c3d83d24f0ad09e87b270bccd13b989029fa01e1562d7b24954622238f425ddadf94b7f71d2908e938d44672d06136bac769c"]),
            )
            .await
            .unwrap();
        println!("{r}");
    }
}
