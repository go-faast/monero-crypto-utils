"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var primitive_ops_1 = require("./primitive_ops");
var constants_1 = require("./constants");
var xmr_str_utils_1 = require("@xmr-core/xmr-str-utils");
var hash_ops_1 = require("./hash_ops");
//creates a Pedersen commitment from an amount (in scalar form) and a mask
//C = bG + aH where b = mask, a = amount
function commit(amount, mask) {
    if (!xmr_str_utils_1.valid_hex(mask) ||
        mask.length !== 64 ||
        !xmr_str_utils_1.valid_hex(amount) ||
        amount.length !== 64) {
        throw Error("invalid amount or mask!");
    }
    var C = primitive_ops_1.ge_double_scalarmult_base_vartime(amount, constants_1.H, mask);
    return C;
}
exports.commit = commit;
function zeroCommit(amount) {
    return commit(amount, constants_1.I);
}
exports.zeroCommit = zeroCommit;
function decode_ecdh(ecdh, key) {
    var first = hash_ops_1.hash_to_scalar(key);
    var second = hash_ops_1.hash_to_scalar(first);
    return {
        mask: primitive_ops_1.sc_sub(ecdh.mask, first),
        amount: primitive_ops_1.sc_sub(ecdh.amount, second),
    };
}
exports.decode_ecdh = decode_ecdh;
function encode_ecdh(ecdh, key) {
    var first = hash_ops_1.hash_to_scalar(key);
    var second = hash_ops_1.hash_to_scalar(first);
    return {
        mask: primitive_ops_1.sc_add(ecdh.mask, first),
        amount: primitive_ops_1.sc_add(ecdh.amount, second),
    };
}
exports.encode_ecdh = encode_ecdh;
function scalarmultH(scalar) {
    return primitive_ops_1.ge_scalarmult(constants_1.H, scalar);
}
exports.scalarmultH = scalarmultH;
//# sourceMappingURL=rct.js.map