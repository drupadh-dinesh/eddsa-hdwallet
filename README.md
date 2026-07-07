# eddsa-hdwallet

`eddsa-hdwallet` is a Go implementation of hierarchical deterministic (HD) wallets for Ed25519 using the Ed25519-BIP32 derivation scheme.

The package provides deterministic key generation from a seed, hardened and non-hardened child derivation, public derivation support, path-based derivation, signing, and serialization of extended keys.

## Features

* Ed25519-BIP32 master key generation
* Hardened child derivation
* Non-hardened child derivation
* Public key derivation from extended public keys
* Path derivation (`m/44'/1815'/0'/0/0`)
* Extended key serialization (`edprv` / `edpub`)
* Ed25519 signing and verification
* Deterministic and concurrency-safe operations
* No external BIP32 dependencies

## Installation

```bash
go get github.com/drupadh-dinesh/eddsa-hdwallet
```

## Quick Start

```go
package main

import (
	"crypto/ed25519"
	"fmt"

	hdwallet "github.com/drupadh-dinesh/eddsa-hdwallet"
)

func main() {
	seed := make([]byte, 32)

	master, err := hdwallet.NewMaster(seed)
	if err != nil {
		panic(err)
	}

	account, err := master.DerivePath("m/44'/0'/0'")
	if err != nil {
		panic(err)
	}

	msg := []byte("hello")
	sig := account.Sign(msg)

	fmt.Println(ed25519.Verify(account.PublicKey(), msg, sig))
}
```

## Creating a Master Key

```go
seed := make([]byte, 32)

master, err := hdwallet.NewMaster(seed)
if err != nil {
	panic(err)
}
```

Seed lengths between 16 and 64 bytes are supported.

## Deriving Child Keys

### Hardened Derivation

```go
child, err := master.Derive(hdwallet.Hardened(0))
```

### Non-Hardened Derivation

```go
child, err := master.Derive(0)
```

### Path Derivation

```go
key, err := master.DerivePath("m/44'/1815'/0'/0/0")
```

## Public Extended Keys

Convert a private extended key into a public extended key:

```go
xpub := master.Neuter()
```

Public extended keys may derive only non-hardened children:

```go
child, err := xpub.Derive(0)
```

Attempting hardened derivation from a public key returns `ErrHardenedPublicChild`.

## Signing

```go
msg := []byte("transaction")

sig := key.Sign(msg)

valid := ed25519.Verify(
	key.PublicKey(),
	msg,
	sig,
)
```

## Serialization

Extended keys can be serialized into portable string representations.

### Private Extended Key

```go
encoded := key.String()
```

Example prefix:

```text
edprv...
```

### Public Extended Key

```go
encoded := key.Neuter().String()
```

Example prefix:

```text
edpub...
```

### Parsing

```go
parsed, err := hdwallet.ParseExtendedKey(encoded)
```

## Fingerprints

Each extended key exposes a 4-byte fingerprint derived from:

```text
RIPEMD160(SHA256(0x00 || publicKey))
```

This matches the fingerprint layout used by SLIP-0010 test vectors.

## Concurrency

All exported operations are read-only and deterministic. The same key may be safely used concurrently for derivation, serialization, and public key generation.

## Errors

Common errors include:

* `ErrInvalidSeed`
* `ErrNilKey`
* `ErrInvalidKey`
* `ErrInvalidPath`
* `ErrHardenedPublicChild`
* `ErrDepthOverflow`
* `ErrInvalidSerialization`
* `ErrChecksumMismatch`

## Specification

This implementation follows the Ed25519-BIP32 hierarchical deterministic
wallet construction described by Khovratovich and Law, supporting both
hardened and non-hardened derivation as well as public child derivation.

It is not compatible with SLIP-0010 implementations that support only
hardened derivation.

## Compatibility

This library implements the Ed25519-BIP32 derivation scheme described by Khovratovich and Law.

Compatibility with other wallets or standards should not be assumed unless explicitly documented.

## Test Vector

Seed:

```text
000102030405060708090a0b0c0d0e0f
```

Master Private Key:

```text
a06a97b52af6fff00be4c4ed75c95ad3f2d0c2cb4f00479c3cd3357259d5cb4ffa907a23207bd40b3d0479212b80c38536bbfc2edb91afa34e5c13db4fb5b652
```

Master Chain Code:

```text
5875ad2aacf5fdf2c6af80087ca701684d97856ffd530e2891c3d5eed54f82a1
```

Master Public Key:

```text
672cee7ab7a38df97244109abd4aafb28593d6bef3735256ccf6f90e8537db59
```

## Security Notice

This project has not yet undergone an independent security audit. If you discover a security vulnerability, cryptographic issue, or any behavior that appears incorrect, please report it by opening a GitHub Issue or contacting the maintainer.

This project welcomes security reviews, bug reports, interoperability testing, and contributions from the community.

## License

See the LICENSE file for details.
