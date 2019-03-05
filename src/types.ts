export interface Commit {
	mask: string;
	amount: string;
}

export interface KeyPair {
	pub: string;
	sec: string;
}

export interface Keys {
	view: KeyPair;
	spend: KeyPair;
}
