"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var xmr_vendor_1 = require("@xmr-core/xmr-vendor");
var xmr_str_utils_1 = require("@xmr-core/xmr-str-utils");
var constants_1 = require("./constants");
var hash_ops_1 = require("./hash_ops");
//curve and scalar functions; split out to make their host functions cleaner and more readable
//inverts X coordinate -- this seems correct ^_^ -luigi1111
function ge_neg(point) {
    if (point.length !== 64) {
        throw Error("expected 64 char hex string");
    }
    return (point.slice(0, 62) +
        ((parseInt(point.slice(62, 63), 16) + 8) % 16).toString(16) +
        point.slice(63, 64));
}
function ge_add(p1, p2) {
    if (p1.length !== 64 || p2.length !== 64) {
        throw Error("Invalid input length!");
    }
    return xmr_str_utils_1.bintohex(xmr_vendor_1.nacl.ge_add(xmr_str_utils_1.hextobin(p1), xmr_str_utils_1.hextobin(p2)));
}
exports.ge_add = ge_add;
//order matters
function ge_sub(point1, point2) {
    var point2n = ge_neg(point2);
    return ge_add(point1, point2n);
}
exports.ge_sub = ge_sub;
//adds two scalars together
function sc_add(scalar1, scalar2) {
    if (scalar1.length !== 64 || scalar2.length !== 64) {
        throw Error("Invalid input length!");
    }
    var scalar1_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    var scalar2_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(scalar1), scalar1_m);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(scalar2), scalar2_m);
    var derived_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto.ccall("sc_add", "void", ["number", "number", "number"], [derived_m, scalar1_m, scalar2_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(derived_m, derived_m + constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto._free(scalar1_m);
    xmr_vendor_1.CNCrypto._free(scalar2_m);
    xmr_vendor_1.CNCrypto._free(derived_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.sc_add = sc_add;
//subtracts one scalar from another
function sc_sub(scalar1, scalar2) {
    if (scalar1.length !== 64 || scalar2.length !== 64) {
        throw Error("Invalid input length!");
    }
    var scalar1_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    var scalar2_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(scalar1), scalar1_m);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(scalar2), scalar2_m);
    var derived_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto.ccall("sc_sub", "void", ["number", "number", "number"], [derived_m, scalar1_m, scalar2_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(derived_m, derived_m + constants_1.STRUCT_SIZES.EC_SCALAR);
    xmr_vendor_1.CNCrypto._free(scalar1_m);
    xmr_vendor_1.CNCrypto._free(scalar2_m);
    xmr_vendor_1.CNCrypto._free(derived_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.sc_sub = sc_sub;
//res = c - (ab) mod l; argument names copied from the signature implementation
function sc_mulsub(sigc, sec, k) {
    if (k.length !== constants_1.KEY_SIZE * 2 ||
        sigc.length !== constants_1.KEY_SIZE * 2 ||
        sec.length !== constants_1.KEY_SIZE * 2 ||
        !xmr_str_utils_1.valid_hex(k) ||
        !xmr_str_utils_1.valid_hex(sigc) ||
        !xmr_str_utils_1.valid_hex(sec)) {
        throw Error("bad scalar");
    }
    var sec_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(sec), sec_m);
    var sigc_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(sigc), sigc_m);
    var k_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(k), k_m);
    var res_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.ccall("sc_mulsub", "void", ["number", "number", "number", "number"], [res_m, sigc_m, sec_m, k_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(res_m, res_m + constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto._free(k_m);
    xmr_vendor_1.CNCrypto._free(sec_m);
    xmr_vendor_1.CNCrypto._free(sigc_m);
    xmr_vendor_1.CNCrypto._free(res_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.sc_mulsub = sc_mulsub;
function ge_double_scalarmult_base_vartime(c, P, r) {
    if (c.length !== 64 || P.length !== 64 || r.length !== 64) {
        throw Error("Invalid input length!");
    }
    return xmr_str_utils_1.bintohex(xmr_vendor_1.nacl.ge_double_scalarmult_base_vartime(xmr_str_utils_1.hextobin(c), xmr_str_utils_1.hextobin(P), xmr_str_utils_1.hextobin(r)));
}
exports.ge_double_scalarmult_base_vartime = ge_double_scalarmult_base_vartime;
function ge_double_scalarmult_postcomp_vartime(r, P, c, I) {
    if (c.length !== 64 ||
        P.length !== 64 ||
        r.length !== 64 ||
        I.length !== 64) {
        throw Error("Invalid input length!");
    }
    var Pb = hash_ops_1.hash_to_ec_2(P);
    return xmr_str_utils_1.bintohex(xmr_vendor_1.nacl.ge_double_scalarmult_postcomp_vartime(xmr_str_utils_1.hextobin(r), xmr_str_utils_1.hextobin(Pb), xmr_str_utils_1.hextobin(c), xmr_str_utils_1.hextobin(I)));
}
exports.ge_double_scalarmult_postcomp_vartime = ge_double_scalarmult_postcomp_vartime;
function ge_scalarmult_base(sec) {
    if (sec.length !== 64) {
        throw Error("Invalid sec length");
    }
    return xmr_str_utils_1.bintohex(xmr_vendor_1.nacl.ge_scalarmult_base(xmr_str_utils_1.hextobin(sec)));
}
exports.ge_scalarmult_base = ge_scalarmult_base;
function ge_scalarmult(pub, sec) {
    if (pub.length !== 64 || sec.length !== 64) {
        throw Error("Invalid input length");
    }
    return xmr_str_utils_1.bintohex(xmr_vendor_1.nacl.ge_scalarmult(xmr_str_utils_1.hextobin(pub), xmr_str_utils_1.hextobin(sec)));
}
exports.ge_scalarmult = ge_scalarmult;
function sc_reduce32(hex) {
    var input = xmr_str_utils_1.hextobin(hex);
    if (input.length !== 32) {
        throw Error("Invalid input length");
    }
    var mem = xmr_vendor_1.CNCrypto._malloc(32);
    xmr_vendor_1.CNCrypto.HEAPU8.set(input, mem);
    xmr_vendor_1.CNCrypto.ccall("sc_reduce32", "void", ["number"], [mem]);
    var output = xmr_vendor_1.CNCrypto.HEAPU8.subarray(mem, mem + 32);
    xmr_vendor_1.CNCrypto._free(mem);
    return xmr_str_utils_1.bintohex(output);
}
exports.sc_reduce32 = sc_reduce32;
//# sourceMappingURL=primitive_ops.js.map