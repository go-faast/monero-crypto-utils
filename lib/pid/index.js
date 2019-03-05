"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var xmr_fast_hash_1 = require("@xmr-core/xmr-fast-hash");
var xmr_constants_1 = require("@xmr-core/xmr-constants");
var xmr_str_utils_1 = require("@xmr-core/xmr-str-utils");
var rand_1 = require("../rand");
var derivation_1 = require("../crypto-ops/derivation");
function makePaymentID() {
    return rand_1.rand_8();
}
exports.makePaymentID = makePaymentID;
function encrypt_payment_id(payment_id, public_key, secret_key) {
    // get the derivation from our passed viewkey, then hash that + tail to get encryption key
    var INTEGRATED_ID_SIZE_BYTES = xmr_constants_1.INTEGRATED_ID_SIZE * 2;
    var ENCRYPTED_PAYMENT_ID_TAIL_BYTE = "8d";
    var derivation = derivation_1.generate_key_derivation(public_key, secret_key);
    var data = "" + derivation + ENCRYPTED_PAYMENT_ID_TAIL_BYTE;
    var pid_key = xmr_fast_hash_1.cn_fast_hash(data).slice(0, INTEGRATED_ID_SIZE_BYTES);
    var encryptedPid = xmr_str_utils_1.hex_xor(payment_id, pid_key);
    return encryptedPid;
}
exports.encrypt_payment_id = encrypt_payment_id;
function isValidOrNoPaymentID(pid) {
    if (!pid) {
        return true;
    }
    return isValidShortPaymentID(pid) || isValidLongPaymentID(pid);
}
exports.isValidOrNoPaymentID = isValidOrNoPaymentID;
function isValidShortPaymentID(payment_id) {
    return isValidPaymentID(payment_id, 16);
}
exports.isValidShortPaymentID = isValidShortPaymentID;
function isValidLongPaymentID(payment_id) {
    console.warn("[WARN]: Long payment (plaintext) ids are deprecated");
    return isValidPaymentID(payment_id, 64);
}
exports.isValidLongPaymentID = isValidLongPaymentID;
function isValidPaymentID(payment_id, length) {
    var pattern = RegExp("^[0-9a-fA-F]{" + length + "}$");
    return pattern.test(payment_id);
}
//# sourceMappingURL=index.js.map