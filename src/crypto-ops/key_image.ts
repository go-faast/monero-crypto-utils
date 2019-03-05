import { CNCrypto } from "@xmr-core/xmr-vendor";
import { KEY_SIZE, STRUCT_SIZES } from "./constants";
import { hextobin, bintohex } from "@xmr-core/xmr-str-utils";
import { hash_to_ec } from "./hash_ops";
import { HWDevice } from "../device";

export async function derive_key_image_from_tx(
	tx_pub: string,
	view_sec: string,
	spend_pub: string,
	spend_sec: string,
	output_index: number,
	hwdev: HWDevice,
) {
	if (tx_pub.length !== 64) {
		throw Error("Invalid tx_pub length");
	}
	if (view_sec.length !== 64) {
		throw Error("Invalid view_sec length");
	}
	if (spend_pub.length !== 64) {
		throw Error("Invalid spend_pub length");
	}
	if (spend_sec.length !== 64) {
		throw Error("Invalid spend_sec length");
	}
	const recv_derivation = await hwdev.generate_key_derivation(
		tx_pub,
		view_sec,
	);

	const ephemeral_sec = await hwdev.derive_secret_key(
		recv_derivation,
		output_index,
		spend_sec,
	);

	const ephemeral_pub = await hwdev.secret_key_to_public_key(ephemeral_sec);

	const key_image = await hwdev.generate_key_image(
		ephemeral_pub,
		ephemeral_sec,
	);
	return {
		ephemeral_pub,
		key_image,
	};
}

export function generate_key_image(pub: string, sec: string) {
	if (!pub || !sec || pub.length !== 64 || sec.length !== 64) {
		throw Error("Invalid input length");
	}
	const pub_m = CNCrypto._malloc(KEY_SIZE);
	const sec_m = CNCrypto._malloc(KEY_SIZE);
	CNCrypto.HEAPU8.set(hextobin(pub), pub_m);
	CNCrypto.HEAPU8.set(hextobin(sec), sec_m);
	if (CNCrypto.ccall("sc_check", "number", ["number"], [sec_m]) !== 0) {
		throw Error("sc_check(sec) != 0");
	}
	const point_m = CNCrypto._malloc(STRUCT_SIZES.GE_P3);
	const point2_m = CNCrypto._malloc(STRUCT_SIZES.GE_P2);
	const point_b = hextobin(hash_to_ec(pub));
	CNCrypto.HEAPU8.set(point_b, point_m);
	const image_m = CNCrypto._malloc(STRUCT_SIZES.KEY_IMAGE);
	CNCrypto.ccall(
		"ge_scalarmult",
		"void",
		["number", "number", "number"],
		[point2_m, sec_m, point_m],
	);
	CNCrypto.ccall(
		"ge_tobytes",
		"void",
		["number", "number"],
		[image_m, point2_m],
	);
	const res = CNCrypto.HEAPU8.subarray(
		image_m,
		image_m + STRUCT_SIZES.KEY_IMAGE,
	);
	CNCrypto._free(pub_m);
	CNCrypto._free(sec_m);
	CNCrypto._free(point_m);
	CNCrypto._free(point2_m);
	CNCrypto._free(image_m);
	return bintohex(res);
}
