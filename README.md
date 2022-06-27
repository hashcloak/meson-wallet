# Meson Wallet

A privacy-first cryptocurrency wallet

1. Build the golang-c bindings.
```BASH
$ go build -o libclient_bindings.so -buildmode=c-shared bindings.go
$ gcc ./examples/ping.c ./libclient_bindings.so -I . -o cping
```

2. Follow the steps at [Meson local testnet](https://github.com/hashcloak/Meson/tree/master/testnet/local) to set up a testnet and update ./client.example.toml.

3. Start the wallet
```BASH
$ cargo run ('config path')
```