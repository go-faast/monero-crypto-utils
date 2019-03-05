"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var xmr_vendor_1 = require("@xmr-core/xmr-vendor");
var xmr_fast_hash_1 = require("@xmr-core/xmr-fast-hash");
var constants_1 = require("./constants");
var xmr_str_utils_1 = require("@xmr-core/xmr-str-utils");
var primitive_ops_1 = require("./primitive_ops");
function hash_to_scalar(buf) {
    var hash = xmr_fast_hash_1.cn_fast_hash(buf);
    var scalar = primitive_ops_1.sc_reduce32(hash);
    return scalar;
}
exports.hash_to_scalar = hash_to_scalar;
function hash_to_ec(key) {
    if (key.length !== constants_1.KEY_SIZE * 2) {
        throw Error("Invalid input length");
    }
    var h_m = xmr_vendor_1.CNCrypto._malloc(constants_1.HASH_SIZE);
    var point_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P2);
    var point2_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P1P1);
    var res_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P3);
    var hash = xmr_str_utils_1.hextobin(xmr_fast_hash_1.cn_fast_hash(key));
    xmr_vendor_1.CNCrypto.HEAPU8.set(hash, h_m);
    xmr_vendor_1.CNCrypto.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
    xmr_vendor_1.CNCrypto.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
    xmr_vendor_1.CNCrypto.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point2_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(res_m, res_m + constants_1.STRUCT_SIZES.GE_P3);
    xmr_vendor_1.CNCrypto._free(h_m);
    xmr_vendor_1.CNCrypto._free(point_m);
    xmr_vendor_1.CNCrypto._free(point2_m);
    xmr_vendor_1.CNCrypto._free(res_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.hash_to_ec = hash_to_ec;
//returns a 32 byte point via "ge_p3_tobytes" rather than a 160 byte "p3", otherwise same as above;
function hash_to_ec_2(key) {
    if (key.length !== constants_1.KEY_SIZE * 2) {
        throw Error("Invalid input length");
    }
    var h_m = xmr_vendor_1.CNCrypto._malloc(constants_1.HASH_SIZE);
    var point_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P2);
    var point2_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P1P1);
    var res_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P3);
    var hash = xmr_str_utils_1.hextobin(xmr_fast_hash_1.cn_fast_hash(key));
    var res2_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.HEAPU8.set(hash, h_m);
    xmr_vendor_1.CNCrypto.ccall("ge_fromfe_frombytes_vartime", "void", ["number", "number"], [point_m, h_m]);
    xmr_vendor_1.CNCrypto.ccall("ge_mul8", "void", ["number", "number"], [point2_m, point_m]);
    xmr_vendor_1.CNCrypto.ccall("ge_p1p1_to_p3", "void", ["number", "number"], [res_m, point2_m]);
    xmr_vendor_1.CNCrypto.ccall("ge_p3_tobytes", "void", ["number", "number"], [res2_m, res_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(res2_m, res2_m + constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto._free(h_m);
    xmr_vendor_1.CNCrypto._free(point_m);
    xmr_vendor_1.CNCrypto._free(point2_m);
    xmr_vendor_1.CNCrypto._free(res_m);
    xmr_vendor_1.CNCrypto._free(res2_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.hash_to_ec_2 = hash_to_ec_2;
exports.hashToPoint = hash_to_ec_2;
function array_hash_to_scalar(array) {
    var buf = "";
    for (var i = 0; i < array.length; i++) {
        buf += array[i];
    }
    return hash_to_scalar(buf);
}
exports.array_hash_to_scalar = array_hash_to_scalar;
//# sourceMappingURL=hash_ops.js.map