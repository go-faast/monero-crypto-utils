"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var xmr_vendor_1 = require("@xmr-core/xmr-vendor");
var constants_1 = require("./constants");
var xmr_str_utils_1 = require("@xmr-core/xmr-str-utils");
var hash_ops_1 = require("./hash_ops");
function generate_key_image(pub, sec) {
    if (!pub || !sec || pub.length !== 64 || sec.length !== 64) {
        throw Error("Invalid input length");
    }
    var pub_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    var sec_m = xmr_vendor_1.CNCrypto._malloc(constants_1.KEY_SIZE);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(pub), pub_m);
    xmr_vendor_1.CNCrypto.HEAPU8.set(xmr_str_utils_1.hextobin(sec), sec_m);
    if (xmr_vendor_1.CNCrypto.ccall("sc_check", "number", ["number"], [sec_m]) !== 0) {
        throw Error("sc_check(sec) != 0");
    }
    var point_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P3);
    var point2_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.GE_P2);
    var point_b = xmr_str_utils_1.hextobin(hash_ops_1.hash_to_ec(pub));
    xmr_vendor_1.CNCrypto.HEAPU8.set(point_b, point_m);
    var image_m = xmr_vendor_1.CNCrypto._malloc(constants_1.STRUCT_SIZES.KEY_IMAGE);
    xmr_vendor_1.CNCrypto.ccall("ge_scalarmult", "void", ["number", "number", "number"], [point2_m, sec_m, point_m]);
    xmr_vendor_1.CNCrypto.ccall("ge_tobytes", "void", ["number", "number"], [image_m, point2_m]);
    var res = xmr_vendor_1.CNCrypto.HEAPU8.subarray(image_m, image_m + constants_1.STRUCT_SIZES.KEY_IMAGE);
    xmr_vendor_1.CNCrypto._free(pub_m);
    xmr_vendor_1.CNCrypto._free(sec_m);
    xmr_vendor_1.CNCrypto._free(point_m);
    xmr_vendor_1.CNCrypto._free(point2_m);
    xmr_vendor_1.CNCrypto._free(image_m);
    return xmr_str_utils_1.bintohex(res);
}
exports.generate_key_image = generate_key_image;
//# sourceMappingURL=key_image.js.map