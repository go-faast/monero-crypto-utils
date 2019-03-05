import { encode_varint } from "@xmr-core/xmr-varint";
import { cn_fast_hash } from "@xmr-core/xmr-fast-hash";
import { ADDRESS_CHECKSUM_SIZE } from "@xmr-core/xmr-constants";
import { cnBase58 } from "@xmr-core/xmr-b58";
import { KeyPair } from "../types";
import {
	NetType,
	cryptonoteBase58PrefixForStandardAddressOn,
} from "../address-utils";
import { ge_scalarmult_base, sc_reduce32 } from "../crypto-ops/primitive_ops";
import { rand_32, random_scalar } from "../rand";

export function secret_key_to_public_key(sec: string) {
	return ge_scalarmult_base(sec);
}

export function pubkeys_to_string(
	spend: string,
	view: string,
	nettype: NetType,
) {
	const prefix = encode_varint(
		cryptonoteBase58PrefixForStandardAddressOn(nettype),
	);
	const data = prefix + spend + view;
	const checksum = cn_fast_hash(data);
	return cnBase58.encode(data + checksum.slice(0, ADDRESS_CHECKSUM_SIZE * 2));
}

// Generate keypair from seed
export function generate_keys(seed: string): KeyPair {
	if (seed.length !== 64) throw Error("Invalid input length!");
	const sec = sc_reduce32(seed);
	const pub = secret_key_to_public_key(sec);
	return {
		sec,
		pub,
	};
}

export function verify_keys(
	view_pub: string,
	view_sec: string,
	spend_pub: string,
	spend_sec: string,
) {
	const expected_view_pub = secret_key_to_public_key(view_sec);
	const expected_spend_pub = secret_key_to_public_key(spend_sec);
	return expected_spend_pub === spend_pub && expected_view_pub === view_pub;
}

export function random_keypair() {
	return generate_keys(rand_32());
}

// alias
export const skGen = random_scalar;
