import { Account, NetType } from "./types";
export declare function is_subaddress(addr: string, nettype: NetType): boolean;
export declare function create_address(seed: string, nettype: NetType): Account;
export declare function decode_address(address: string, nettype: NetType): {
    spend: string;
    view: string;
    intPaymentId: string;
} | {
    spend: string;
    view: string;
    intPaymentId?: undefined;
};
export declare function isValidAddress(address: string, netType: NetType): boolean;
export declare function makeIntegratedAddressFromAddressAndShortPid(address: string, short_pid: string, nettype: NetType): string;
export declare function cryptonoteBase58PrefixForStandardAddressOn(nettype: NetType): 18 | 53 | 24;
export declare function cryptonoteBase58PrefixForIntegratedAddressOn(nettype: NetType): 19 | 54 | 25;
export declare function cryptonoteBase58PrefixForSubAddressOn(nettype: NetType): 42 | 63 | 36;
//# sourceMappingURL=utils.d.ts.map