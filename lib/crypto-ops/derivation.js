"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var xmr_vendor_1 = require("@xmr-core/xmr-vendor");
var constants_1 = require("./constants");
var xmr_varint_1 = require("@xmr-core/xmr-varint");
var hash_ops_1 = require("./hash_ops");
var primitive_ops_1 = require("./primitive_ops");
var xmr_str_utils_1 = require("@xmr-core/xmr-str-utils");
function generate_key_derivation(pub, sec) {
    if (pub.length !== 64 || sec.length !== 64) {
        throw Error("Invalid input length");
    }
    var P = primitive_ops_1.ge_scalarmult(pub, sec);
    return primitive_ops_1.ge_scalarmult(P, xmr_str_utils_1.d2s("8")); //mul8 to ensure group
}
exports.generate_key_derivation = generate_key_derivation;
function derivation_to_scalar(derivation, output_index) {
    var buf = "";
    if (derivation.length !== constants_1.STRUCT_SIZES.EC_POINT * 2) {
        throw Error("Invalid derivation length!");
    }
    buf += derivation;
    var enc = xmr_varint_1.encode_varint(output_index);
    if (enc.length > 10 * 2) {
        throw Error("output_index didn't fit in 64-bit varint");
    }
    buf += enc;
    return hash_ops_1.hash_to_scalar(buf);
}
exports.derivation_to_scalar = derivation_to_scalar;
function derive_secret_key(derivation, out_index, sec) {
    if (derivation.length !== 64 || sec.length !== 64) {
        throw Error("Invalid input length!");
    }
    var scalar_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    var scalar_b = xmr_str_utils_1.hextobin(derivation_to_scalar(derivation, out_index));
    xmr_vendor_1.CNCrypto.HEAPU8.set(scalar_b, scalar_m);
    var base_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(sec), base_m);
    var derived_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto.ccall("sc_add", "void", ["number", "number", "number"], [derived_m, base_m, scalar_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(derived_m, derived_m + constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto._free(scalar_m);
    xmr_vendor_1.CNCrypto._free(base_m);
    xmr_vendor_1.CNCrypto._free(derived_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.derive_secret_key = derive_secret_key;
function derive_public_key(derivation, out_index, pub) {
    if (derivation.length !== 64 || pub.length !== 64) {
        throw Error("Invalid input length!");
    }
    var s = derivation_to_scalar(derivation, out_index);
    return xmr_str_utils_1.bintohex(xmr_vendor_1.nacl.ge_add(xmr_str_utils_1.hextobin(pub), xmr_str_utils_1.hextobin(primitive_ops_1.ge_scalarmult_base(s))));
}
exports.derive_public_key = derive_public_key;
// D' = P - Hs(aR|i)G
function derive_subaddress_public_key(output_key, derivation, out_index) {
    if (output_key.length !== 64 || derivation.length !== 64) {
        throw Error("Invalid input length!");
    }
    var scalar = derivation_to_scalar(derivation, out_index);
    var point = primitive_ops_1.ge_scalarmult_base(scalar);
    return primitive_ops_1.ge_sub(output_key, point);
}
exports.derive_subaddress_public_key = derive_subaddress_public_key;
//# sourceMappingURL=derivation.js.map