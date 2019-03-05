export declare function makePaymentID(): string;
export declare function encrypt_payment_id(payment_id: string, public_key: string, secret_key: string): string;
export declare function isValidOrNoPaymentID(pid?: string | null): boolean;
export declare function isValidShortPaymentID(payment_id: string): boolean;
export declare function isValidLongPaymentID(payment_id: string): boolean;
//# sourceMappingURL=index.d.ts.map