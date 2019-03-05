import { KeyPair } from "../types";

export interface Account {
	spend: KeyPair;
	view: KeyPair;
	public_addr: string;
}

export enum NetType {
	MAINNET = 0,
	TESTNET = 1,
	STAGENET = 2,
}
