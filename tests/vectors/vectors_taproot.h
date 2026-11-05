#ifndef VECTORS_TAPROOT_H
#define VECTORS_TAPROOT_H

/* spec: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0086.mediawiki
 * sha256 d8d01dee331da07c2562615bc1f064c1868ec3fce61184973da76d1196c7f5b0
 *
 * Three leaves of the BIP-86 test vector. The document publishes the account xpub they derive
 * from publicly, each leaf's own xprv, the x-only internal key and the output key. The generator
 * first recomputes the internal key from the private key and then the output key from the internal
 * key and its TapTweak, so the published quadruple is consistent with the standard before any of
 * it reaches a test.
 *
 * 2 of these internal keys have an even y and 1 an odd one, which is the difference
 * between handing the point to the tweak as it stands and negating it first. The internal buffer
 * is the layout bip32_ctx_t.leaf_pub holds: a SEC1 compression prefix, then x || y.
 */
typedef struct {
  const char* path;
  const char* account_pub; /* the account xpub, 0x04 || x || y */
  const char* account_chain;
  unsigned change;
  unsigned index;
  const char* internal; /* 0x02|parity || x || y */
  const char* witprog;
} taproot_t;

static const taproot_t TAPROOT_OUTPUT_KEY[] = {
  {"m/86H/0H/0H/0/0", "04418278a2885c8bb98148158d1474634097a179c642f23cf1cc04da629ac6f0fb7d772ca0939497d3c25302c2ece5110b71826de66e8a104fd1b9d7a94315658d", "c61a8f27e98182314d2444da3e600eb5836ec8ad183c86c311f95df8082b18aa", 0U, 0U, "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc1158190abf51fae206f0a1c825717ed512366620dad8c82b09807e7f27986e5c3fb", "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"},
  {"m/86H/0H/0H/0/1", "04418278a2885c8bb98148158d1474634097a179c642f23cf1cc04da629ac6f0fb7d772ca0939497d3c25302c2ece5110b71826de66e8a104fd1b9d7a94315658d", "c61a8f27e98182314d2444da3e600eb5836ec8ad183c86c311f95df8082b18aa", 0U, 1U, "0283dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145c44980cbde53294c991e434ff1b0343ffa66fbffe1f06525703e5509d227c1aa", "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"},
  {"m/86H/0H/0H/1/0", "04418278a2885c8bb98148158d1474634097a179c642f23cf1cc04da629ac6f0fb7d772ca0939497d3c25302c2ece5110b71826de66e8a104fd1b9d7a94315658d", "c61a8f27e98182314d2444da3e600eb5836ec8ad183c86c311f95df8082b18aa", 1U, 0U, "02399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef3c544ce1493910ad1656e05b104ee56d707f9f2046935224041cd16ddadbf248", "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"}
};

#define TAPROOT_OUTPUT_KEY_COUNT (sizeof(TAPROOT_OUTPUT_KEY) / sizeof(TAPROOT_OUTPUT_KEY[0]))

#endif /* VECTORS_TAPROOT_H */
