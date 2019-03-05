import { cn_fast_hash } from "@xmr-core/xmr-fast-hash";
import { INTEGRATED_ID_SIZE } from "@xmr-core/xmr-constants";
import { hex_xor } from "@xmr-core/xmr-str-utils";
import { rand_8 } from "../rand";
import { generate_key_derivation } from "../crypto-ops/derivation";

export function makePaymentID() {
	return rand_8();
}

export function encrypt_payment_id(
	payment_id: string,
	public_key: string,
	secret_key: string,
) {
	// get the derivation from our passed viewkey, then hash that + tail to get encryption key
	const INTEGRATED_ID_SIZE_BYTES = INTEGRATED_ID_SIZE * 2;
	const ENCRYPTED_PAYMENT_ID_TAIL_BYTE = "8d";

	const derivation = generate_key_derivation(public_key, secret_key);
	const data = `${derivation}${ENCRYPTED_PAYMENT_ID_TAIL_BYTE}`;
	const pid_key = cn_fast_hash(data).slice(0, INTEGRATED_ID_SIZE_BYTES);

	const encryptedPid = hex_xor(payment_id, pid_key);

	return encryptedPid;
}

export function isValidOrNoPaymentID(pid?: string | null) {
	if (!pid) {
		return true;
	}

	return isValidShortPaymentID(pid) || isValidLongPaymentID(pid);
}

export function isValidShortPaymentID(payment_id: string) {
	return isValidPaymentID(payment_id, 16);
}

export function isValidLongPaymentID(payment_id: string) {
	console.warn("[WARN]: Long payment (plaintext) ids are deprecated");
	return isValidPaymentID(payment_id, 64);
}

function isValidPaymentID(payment_id: string, length: 16 | 64) {
	const pattern = RegExp("^[0-9a-fA-F]{" + length + "}$");
	return pattern.test(payment_id);
}
