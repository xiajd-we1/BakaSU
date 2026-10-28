#ifndef MANAGER_SIGN_H
#define MANAGER_SIGN_H

// tiann/KernelSU
#define EXPECTED_SIZE_OFFICIAL 0x033b
#define EXPECTED_HASH_OFFICIAL "c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"

// Baka-SU/BakaSU
#define EXPECTED_SIZE_BAKASU 0x377
#define EXPECTED_HASH_BAKASU "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64"

/*
 * This tree's own manager build.
 *
 * The CI build-manager job produces an APK signed with a throwaway keystore,
 * and repack-manager (which injects libksud.so) cannot run at all on a fork
 * without the PROD_KEYSTORE secret. The result is a perfectly functional
 * manager whose certificate is in nobody's whitelist, so the kernel never
 * crowns it as manager and every ksu ioctl fails - the UI then reports
 * "KernelSU driver not detected".
 *
 * Whitelisting the locally produced certificate fixes that without touching
 * the upstream entries: the official BakaSU / KernelSU / KOWX712 managers keep
 * working, and this build gets the same treatment.
 *
 * Values are the SHA-256 of the certificate DER inside the v2 signing block,
 * not the apksigner fingerprint - the kernel hashes the raw certificate.
 * Recompute with: python3 scripts/print_apk_cert_hash.py <apk>
 */
#define EXPECTED_SIZE_VENUS_DEBUG 0x313
#define EXPECTED_HASH_VENUS_DEBUG "33f43900368993652d3a407940ca76b9e2da67ec75aafc762b210b9634b38d3d"

// KOWX712/KernelSU
#define EXPECTED_SIZE_KOWX712 0x375
#define EXPECTED_HASH_KOWX712 "484fcba6e6c43b1fb09700633bf2fb4758f13cb0b2f4457b80d075084b26c588"

typedef struct {
    unsigned size;
    const char *sha256;
} apk_sign_key_t;

#endif /* MANAGER_SIGN_H */
