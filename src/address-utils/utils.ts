import { encode_varint } from "@xmr-core/xmr-varint";
import { cn_fast_hash } from "@xmr-core/xmr-fast-hash";
import { cnBase58 } from "@xmr-core/xmr-b58";
import {
	INTEGRATED_ID_SIZE,
	ADDRESS_CHECKSUM_SIZE,
} from "@xmr-core/xmr-constants";
import { Account, NetType } from "./types";
import { sc_reduce32 } from "../crypto-ops/primitive_ops";
import { generate_keys, pubkeys_to_string } from "../key-utils";

export function is_subaddress(addr: string, nettype: NetType) {
	const decoded = cnBase58.decode(addr);
	const subaddressPrefix = encode_varint(
		cryptonoteBase58PrefixForSubAddressOn(nettype),
	);
	const prefix = decoded.slice(0, subaddressPrefix.length);
	return prefix === subaddressPrefix;
}

export function create_address(seed: string, nettype: NetType): Account {
	// updated by Luigi and PS to support reduced and non-reduced seeds
	let first;
	if (seed.length !== 64) {
		first = cn_fast_hash(seed);
	} else {
		first = sc_reduce32(seed);
	}
	const spend = generate_keys(first);
	const second = cn_fast_hash(first);
	const view = generate_keys(second);
	const public_addr = pubkeys_to_string(spend.pub, view.pub, nettype);
	return { spend, view, public_addr };
}

export function decode_address(address: string, nettype: NetType) {
	let dec = cnBase58.decode(address);
	const expectedPrefix = encode_varint(
		cryptonoteBase58PrefixForStandardAddressOn(nettype),
	);
	const expectedPrefixInt = encode_varint(
		cryptonoteBase58PrefixForIntegratedAddressOn(nettype),
	);
	const expectedPrefixSub = encode_varint(
		cryptonoteBase58PrefixForSubAddressOn(nettype),
	);
	const prefix = dec.slice(0, expectedPrefix.length);
	if (
		prefix !== expectedPrefix &&
		prefix !== expectedPrefixInt &&
		prefix !== expectedPrefixSub
	) {
		throw Error("Invalid address prefix");
	}
	dec = dec.slice(expectedPrefix.length);
	const spend = dec.slice(0, 64);
	const view = dec.slice(64, 128);
	let checksum;
	let expectedChecksum;
	let intPaymentId;

	if (prefix === expectedPrefixInt) {
		intPaymentId = dec.slice(128, 128 + INTEGRATED_ID_SIZE * 2);
		checksum = dec.slice(
			128 + INTEGRATED_ID_SIZE * 2,
			128 + INTEGRATED_ID_SIZE * 2 + ADDRESS_CHECKSUM_SIZE * 2,
		);
		expectedChecksum = cn_fast_hash(
			prefix + spend + view + intPaymentId,
		).slice(0, ADDRESS_CHECKSUM_SIZE * 2);
	} else {
		checksum = dec.slice(128, 128 + ADDRESS_CHECKSUM_SIZE * 2);
		expectedChecksum = cn_fast_hash(prefix + spend + view).slice(
			0,
			ADDRESS_CHECKSUM_SIZE * 2,
		);
	}
	if (checksum !== expectedChecksum) {
		throw Error("Invalid checksum");
	}
	if (intPaymentId) {
		return {
			spend: spend,
			view: view,
			intPaymentId: intPaymentId,
		};
	} else {
		return {
			spend: spend,
			view: view,
		};
	}
}

export function makeIntegratedAddressFromAddressAndShortPid(
	address: string,
	short_pid: string,
	nettype: NetType,
) {
	// throws
	let decoded_address = decode_address(
		address, // TODO/FIXME: not super happy about having to decode just to re-encode… this was a quick hack
		nettype,
	); // throws
	if (!short_pid || short_pid.length != 16) {
		throw Error("expected valid short_pid");
	}
	const prefix = encode_varint(
		cryptonoteBase58PrefixForIntegratedAddressOn(nettype),
	);
	const data =
		prefix + decoded_address.spend + decoded_address.view + short_pid;
	const checksum = cn_fast_hash(data);
	const encodable__data = data + checksum.slice(0, ADDRESS_CHECKSUM_SIZE * 2);
	//
	return cnBase58.encode(encodable__data);
}

const __MAINNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 18;
const __MAINNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 19;
const __MAINNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 42;

const __TESTNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 53;
const __TESTNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54;
const __TESTNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;

const __STAGENET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 24;
const __STAGENET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25;
const __STAGENET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 36;

export function cryptonoteBase58PrefixForStandardAddressOn(nettype: NetType) {
	if (nettype === NetType.MAINNET) {
		return __MAINNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
	} else if (nettype === NetType.TESTNET) {
		return __TESTNET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
	} else if (nettype === NetType.STAGENET) {
		return __STAGENET_CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
	}
	throw Error("Illegal nettype");
}

export function cryptonoteBase58PrefixForIntegratedAddressOn(nettype: NetType) {
	if (nettype === NetType.MAINNET) {
		return __MAINNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
	} else if (nettype === NetType.TESTNET) {
		return __TESTNET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
	} else if (nettype === NetType.STAGENET) {
		return __STAGENET_CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
	}
	throw Error("Illegal nettype");
}

export function cryptonoteBase58PrefixForSubAddressOn(nettype: NetType) {
	if (nettype === NetType.MAINNET) {
		return __MAINNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
	} else if (nettype === NetType.TESTNET) {
		return __TESTNET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
	} else if (nettype === NetType.STAGENET) {
		return __STAGENET_CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
	}
	throw Error("Illegal nettype");
}
