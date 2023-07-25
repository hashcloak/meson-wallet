# Meson Wallet

A privacy-first cryptocurrency wallet

1. Build the golang-c bindings.
```BASH
$ go build -o ./lib/libclient_bindings.so -buildmode=c-shared ./lib/bindings.go
```

2. Follow the steps at [Meson local testnet](https://github.com/hashcloak/Meson/tree/master/testnet/local) to set up a testnet and update ./client.example.toml.

3. Start the wallet
```BASH
$ cargo run ('config path')
```

## Erc4337 Wallet

Currently erc4337 wallet have not integraded with meson yet. Please use test functions within `src/erc4337wallet.rs` to test it.

1. Install smart contract dependencies with foundry.
```Bash
$ cd smartWallet
$ forge install
```

2. Create `smartWallet/.env` and deploy smart contracts to network of choice with `smartWallet/script/Deploy.s.sol` as decribed in [Foundry Book](https://book.getfoundry.sh/tutorials/solidity-scripting#deploying-our-contract).

3. Setup a local bundler if testing on a local network.

4. Upate addresses in `src/create_sender_util.rs`.(We will put all configs in a sigle file in futuer version.)

5. Run `$cargo run` to create an EOA account first as we need it for the contract wallet's owner in the current version.

5. Use `test_create_account()`, `test_send_userop()` inside `src/erc4337wallet.rs` to send a erc4337 userOp.

## Tornado cash support
1. Git clone [tornado-core](https://github.com/tornadocash/tornado-core), and replace `tornado-core/contracts/Verifier.sol` with `Meson-Wallet/src/circuits/Verifier.sol`.

2. Follow instructions on [tornado-core](https://github.com/tornadocash/tornado-core) to deploy contracts.

3. Update tornado cash address in `src/tornado_util.rs`.

4. Use `test_tornado_deposit()`, `test_tornado_withdraw()` inside `src/erc4337wallet.rs` to send a erc4337 userOp.



