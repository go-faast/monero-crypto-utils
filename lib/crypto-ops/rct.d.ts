import { Commit } from "../types";
export declare function commit(amount: string, mask: string): string;
export declare function zeroCommit(amount: string): string;
export declare function decode_ecdh(ecdh: Commit, key: string): Commit;
export declare function encode_ecdh(ecdh: Commit, key: string): Commit;
export declare function scalarmultH(scalar: string): string;
//# sourceMappingURL=rct.d.ts.map