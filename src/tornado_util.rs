use ark_bn254::{Bn254, Config};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::Groth16;
use babyjubjub_rs::{decompress_point, Fr, Point};
use ethers::abi::{AbiEncode, Address};
use ethers::prelude::{abigen, Bytes, Filter, Middleware, Provider, U256};
use ethers::utils;
use ff_ce::{from_hex, Field, PrimeField};
use mimc_sponge_rs::Fr as mimc_fr;
use num_bigint::BigInt;
use pedersen_hash_rs::pedersen_hash;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use sparse_merkle_tree::{default_hash, MerkleTree};
use std::str::FromStr;
use std::sync::Arc;

type GrothBn = Groth16<Bn254>;

abigen!(Tornado, "src/ETHTornado.json");
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
const TORNADO_ADDRESS: &str = "0xDF4146e8616515d88e6F9c3448245F6404Bc5929";
const MERKLE_LEVEL: usize = 20;
impl Deposit {
    pub fn new() -> Self {
        //let rng = thread_rng();
        let mut r = StdRng::seed_from_u64(10);
        let nullifier_random_bytes = r.gen::<[u8; 31]>();
        let nullifier = BigInt::from_bytes_le(num_bigint::Sign::Plus, &nullifier_random_bytes);
        let secret_random_bytes = r.gen::<[u8; 31]>();
        let secret = BigInt::from_bytes_le(num_bigint::Sign::Plus, &secret_random_bytes);
        let preimage = [
            nullifier_random_bytes.as_slice(),
            secret_random_bytes.as_slice(),
        ]
        .concat();

        let commitment = decompress_point(pedersen_hash(&preimage)).unwrap().x;
        let commitment_hex = format!("0x{}", ff_ce::to_hex(&commitment));
        let nullifier_hash = decompress_point(pedersen_hash(&nullifier_random_bytes))
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

    pub fn gen_deposit_tx(&self, currency: Option<String>, amount: String) -> Vec<u8> {
        let currency = currency.unwrap_or("eth".into());
        let preimage_hex = utils::hex::encode(&self.preimage);
        let net_id = 1;
        let note_string = format!("tornado-{currency}-{amount}-{net_id}-{preimage_hex}");
        let value = utils::parse_ether(amount).unwrap();
        let deposit_sig = Bytes::from_str(DEPOSIT_SIGNATURE).unwrap().to_vec();
        let commitment_vec = Bytes::from_str(&self.commitment_hex).unwrap().to_vec();
        let tx_vec = [deposit_sig, commitment_vec].concat();

        tx_vec
    }
}

pub async fn generate_merkle_proof(deposit: Deposit) -> (Vec<mimc_fr>, Vec<u128>, mimc_fr) {
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
    let tree = MerkleTree::new(MERKLE_LEVEL, None, default_hash, Some(leaves));
    let root = tree.root();
    let (pathElements, pathIndices) = tree.path(index);
    return (pathElements, pathIndices, root);
}

pub fn generate_proof(deposit: Deposit) {
    let cfg =
        CircomConfig::<Bn254>::new("src/circuits/withdraw.wasm", "src/circuits/withdraw.r1cs")
            .unwrap();
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

    const HTTP_URL: &str = "https://rpc.flashbots.net";
    const V3FACTORY_ADDRESS: &str = "0x1F98431c8aD98523631AE4a59f267346ea31F984";
    const DAI_ADDRESS: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    const USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

    #[test]
    pub fn test_deposit() {
        let d = Deposit::new();

        let tx = d.gen_deposit_tx(None, "0.1".into());
        println!("{:?}", tx);
    }

    #[tokio::test]
    pub async fn test_log() {
        let provider = Provider::<Http>::try_from(HTTP_URL).unwrap();
        let client = Arc::new(provider);
        let token_topics = vec![
            H256::from(USDC_ADDRESS.parse::<H160>().unwrap()),
            H256::from(USDT_ADDRESS.parse::<H160>().unwrap()),
            H256::from(DAI_ADDRESS.parse::<H160>().unwrap()),
        ];
        let filter = Filter::new()
            .address(V3FACTORY_ADDRESS.parse::<Address>().unwrap())
            .event("PoolCreated(address,address,uint24,int24,address)")
            .topic1(token_topics.to_vec())
            .topic2(token_topics.to_vec())
            .from_block(0);
        let logs = client.get_logs(&filter).await.unwrap();
        println!("{} pools found!", logs.iter().len());
        for log in logs.iter() {
            let token0 = Address::from(log.topics[1]);
            let token1 = Address::from(log.topics[2]);
            let fee_tier = U256::from_big_endian(&log.topics[3].as_bytes()[29..32]);
            let tick_spacing = U256::from_big_endian(&log.data[29..32]);
            let pool = Address::from(&log.data[44..64].try_into().unwrap());
            println!("{}", log.data);
            println!(
            "pool = {pool}, token0 = {token0}, token1 = {token1}, fee = {fee_tier}, spacing = {tick_spacing}"
        );
        }
    }

    #[tokio::test]
    pub async fn test_merkle() {
        let d = Deposit::new();
        generate_merkle_proof(d).await;
    }

    #[tokio::test]
    pub async fn test_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:8545";
        let provider = Provider::try_from(rpc_url).unwrap();
        let r: String = provider
            .request(
                "eth_call",
                json!([{
                    "to":"0x7829eB3f548AA829244C10bE9e52c4986568a624",
                    "data":"0x6d9833e3289e40c81cbfe7775e60ecf5ccb64949914b56ef575603a74a93c35f8ba21160",
                }]),
            )
            .await
            .unwrap();
        println!("{r}");
    }

    #[tokio::test]
    pub async fn test_sign_deposit_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:8545";
        let deposit = Deposit::new();
        let tx = deposit.gen_deposit_tx(None, "0.1".into());
        let data = "0x".to_owned() + &utils::hex::encode(tx);
        let provider = Provider::try_from(rpc_url).unwrap();
        let r: String = provider
            .request(
                "eth_signTransaction",
                json!([{
                    "from":"0xe35118eAD858Ea984c0075c5c45ce5ECA2E43b33",
                    "to":"0xDF4146e8616515d88e6F9c3448245F6404Bc5929",
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
                json!(["0x02f89b82053980853a35294400853a352944008398968094df4146e8616515d88e6f9c3448245f6404bc592988016345785d8a0000a4b214faa52d68c038325f51d266e886116e885f7c4488c68aafc0ba315c8f1b7995d38547c001a0bb7443a75e2a1569abe8090e817666ef40665f99e17c0d04cdf5035def38b10aa04c43f8009347f2c8dc2d7a5de1cbc9c03d3514fe32e5d30f128b0561fc68b770"]),
            )
            .await
            .unwrap();
        println!("{r}");
    }

    #[test]
    pub fn test_proof() {
        let deposit = Deposit::new();
        generate_proof(deposit);
    }
}
