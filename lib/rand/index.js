"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto_1 = require("crypto");
var primitive_ops_1 = require("../crypto-ops/primitive_ops");
// Generate a 256-bit / 64-char / 32-byte crypto random
function rand_32() {
    return crypto_1.randomBytes(32).toString("hex");
}
exports.rand_32 = rand_32;
// Generate a 64-bit / 16-char / 8-byte crypto random
function rand_8() {
    return crypto_1.randomBytes(8).toString("hex");
}
exports.rand_8 = rand_8;
// Random 32-byte ec scalar
function random_scalar() {
    return primitive_ops_1.sc_reduce32(rand_32());
}
exports.random_scalar = random_scalar;
//# sourceMappingURL=index.js.map