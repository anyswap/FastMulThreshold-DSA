package smpc

const EC256K1 string = "EC256K1"
const ED25519 string = "ED25519"
const EC256STARK string = "EC256STARK"
const SR25519 string = "SR25519"

var VALID_SIG_TYPES = []string{EC256K1, ED25519, EC256STARK, SR25519}