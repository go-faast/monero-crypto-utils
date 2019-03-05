# monero-crypto-utils

A fork of @xmr-core/xmr-crypto-utils without any ledger device functions and dependencies.

## Features

---

-   Key image generation
-   RCT operations such as Pedersen commitments, ECDH encode/decode
-   Hash operations such as `hash_to_scalar`, `hash_to_ec`
-   Derivation operations such as generating key derivations, deriving private and public keys
-   Primitive functions for curve and scalar functions
-   Converting private keys to public keys
-   Generating new keypairs
-   Verifying keypairs
-   Checking for subaddresses
-   Creating addresses based on seeds
-   Creating integrated addresses from normal addresses and a payment id
-   Decoding address strings into their public key components
-   Get address prefix for standard addresses
-   Get address prefix for integrated addresses
-   Get address prefix for subaddresses
-   Random 256 bit hex strings
-   Random 64 bit hex strings
-   Random 32-byte ec scalars
-   Check if a string contains a payment id
-   Check if a payment id is a short(encrypted) or long(plaintext) id
-   Encrypt/Decrypt a payment id with a keypair
-   Generate a payment id
-   Validate an address

## Usage

---

```ts
import { isValidAddress, NetType } from "monero-crypto-utils";
isValidAddress('4AqM9s31...', NetType.MAINNET)
```

## Installation

---

Install by running:

```sh
npm install go-faast/monero-crypto-utils
```

## License

---

The project is licensed under the MIT license.
