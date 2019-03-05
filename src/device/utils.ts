import { HWDevice } from "./types";
import { LedgerDevice } from "./device-ledger";
import { NetType } from "../address-utils/types";
import { pubkeys_to_string } from "../key-utils";

/**
 * @description Returns true if the device is a real device (only ledger for now)
 *
 * @export
 * @param {HWDevice} hwdev
 * @returns {hwdev is LedgerDevice}
 */
export function isRealDevice(hwdev: HWDevice): hwdev is LedgerDevice<any> {
	return hwdev instanceof LedgerDevice;
}

export async function getAddressString(
	hwdev: HWDevice,
	nettype: NetType = NetType.MAINNET,
) {
	const {
		spend_public_key,
		view_public_key,
	} = await hwdev.get_public_address();

	const address = pubkeys_to_string(
		spend_public_key,
		view_public_key,
		nettype,
	);

	return address;
}
