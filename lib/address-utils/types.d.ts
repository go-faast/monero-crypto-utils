import { KeyPair } from "../types";
export interface Account {
    spend: KeyPair;
    view: KeyPair;
    public_addr: string;
}
export declare enum NetType {
    MAINNET = 0,
    TESTNET = 1,
    STAGENET = 2
}
//# sourceMappingURL=types.d.ts.map