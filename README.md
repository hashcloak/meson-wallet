# Meson Wallet

A privacy-first cryptocurrency wallet

test binding:
```BASH
$ go build -o client_bindings.so -buildmode=c-shared bindings.go
$ gcc ./examples/ping.c ./client_bindings.so -I . -o cping
```