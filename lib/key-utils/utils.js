"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var xmr_varint_1 = require("@xmr-core/xmr-varint");
var xmr_fast_hash_1 = require("@xmr-core/xmr-fast-hash");
var xmr_constants_1 = require("@xmr-core/xmr-constants");
var xmr_b58_1 = require("@xmr-core/xmr-b58");
var address_utils_1 = require("../address-utils");
var primitive_ops_1 = require("../crypto-ops/primitive_ops");
var rand_1 = require("../rand");
function secret_key_to_public_key(sec) {
    return primitive_ops_1.ge_scalarmult_base(sec);
}
exports.secret_key_to_public_key = secret_key_to_public_key;
function pubkeys_to_string(spend, view, nettype) {
    var prefix = xmr_varint_1.encode_varint(address_utils_1.cryptonoteBase58PrefixForStandardAddressOn(nettype));
    var data = prefix + spend + view;
    var checksum = xmr_fast_hash_1.cn_fast_hash(data);
    return xmr_b58_1.cnBase58.encode(data + checksum.slice(0, xmr_constants_1.ADDRESS_CHECKSUM_SIZE * 2));
}
exports.pubkeys_to_string = pubkeys_to_string;
// Generate keypair from seed
function generate_keys(seed) {
    if (seed.length !== 64)
        throw Error("Invalid input length!");
    var sec = primitive_ops_1.sc_reduce32(seed);
    var pub = secret_key_to_public_key(sec);
    return {
        sec: sec,
        pub: pub,
    };
}
exports.generate_keys = generate_keys;
function verify_keys(view_pub, view_sec, spend_pub, spend_sec) {
    var expected_view_pub = secret_key_to_public_key(view_sec);
    var expected_spend_pub = secret_key_to_public_key(spend_sec);
    return expected_spend_pub === spend_pub && expected_view_pub === view_pub;
}
exports.verify_keys = verify_keys;
function random_keypair() {
    return generate_keys(rand_1.rand_32());
}
exports.random_keypair = random_keypair;
// alias
exports.skGen = rand_1.random_scalar;
//# sourceMappingURL=utils.js.map