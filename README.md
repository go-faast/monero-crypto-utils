# @xmr-core/xmr-crypto-utils

Core crypto operations for Monero

## Features

---

-   Key image generation
-   RCT operations such as Pedersen commitments, ECDH encode/decode
-   Hash operations such as `hash_to_scalar`, `hash_to_ec`
-   Derivation operations such as generating key derivations, deriving private and public keys
-   Primitive functions for curve and scalar functions
-   Ledger Nano S implementation under `device-ledger`
-   "Default" device implementation for unified api usage for private keys
-   Device interface to conform to for future hardware device implementations like Trezor
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

## Usage

---

```ts
import { generate_key_image } from "@xmr-core/xmr-crypto-utils";
const secretKey = "...";
const publicKey = "...";
const keyImage = generate_key_image(publicKey, secretKey);
```

See `@xmr-core/xmr-transaction` to see how the device portions of `@xmr-core/xmr-crypto-utils` is used in the context of creating transactions, or `@xmr-core/xmr-mymonero-libs` to see how its used for checking if transactions belong to the current hardware device being used.

## Installation

---

Install @xmr-core/xmr-crypto-utils by running:

```sh
yarn add @xmr-core/xmr-crypto-utils
```

## License

---

The project is licensed under the MIT license.
