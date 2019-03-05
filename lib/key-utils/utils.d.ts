import { KeyPair } from "../types";
import { NetType } from "../address-utils";
import { random_scalar } from "../rand";
export declare function secret_key_to_public_key(sec: string): string;
export declare function pubkeys_to_string(spend: string, view: string, nettype: NetType): string;
export declare function generate_keys(seed: string): KeyPair;
export declare function verify_keys(view_pub: string, view_sec: string, spend_pub: string, spend_sec: string): boolean;
export declare function random_keypair(): KeyPair;
export declare const skGen: typeof random_scalar;
//# sourceMappingURL=utils.d.ts.map