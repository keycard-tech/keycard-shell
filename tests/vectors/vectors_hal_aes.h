#ifndef VECTORS_HAL_AES_H
#define VECTORS_HAL_AES_H

/* spec: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
 * sha256 89c6da9e6cb81ffb7c115752b789ff3dc205acb2b13d6a36ff55acc79e87f61e
 * spec: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
 * sha256 16ec6f99424192757b5b9928a7dcf41817be3aaf85d48366740dfdf7c16db250
 *
 * The block vector is FIPS-197 Appendix C.3, the AES-256 known-answer pair.
 *
 * The CCM cases below are the device's shape -- 13-byte nonce, 8-byte tag, no associated data -- and no
 * published vector has it: SP 800-38C's examples all carry associated data, and RFC 3610's are all
 * 8-byte nonces with associated data too. So they are emitted only where ccm_spec(), composed from
 * SP 800-38C 5.2 and Appendix A rather than from aes_ccm.c, and pycryptodome's own CCM agree; the
 * generator aborts otherwise. Appendix C Examples 1, 2 and 3 are checked the same way before anything is
 * written, which is what keeps that model honest at the points that are published. Example 4 is not
 * checked, because neither implementation reproduces the C and T the document prints. Example 3 is the
 * one published case an 8-byte tag can express, so it is carried through below as a vector of its own.
 */

/* FIPS-197 C.3 */
#define AES256_BLOCK_KEY "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define AES256_BLOCK_PLAINTEXT "00112233445566778899aabbccddeeff"
#define AES256_BLOCK_CIPHERTEXT "8ea2b7ca516745bfeafc49904b496089"

typedef struct {
  const char* key;
  const char* nonce;
  const char* aad;
  const char* plaintext;
  const char* out; /* ciphertext then tag, as aes128_ccm_encrypt() lays them down */
} aes_ccm_kat_t;

/* SP 800-38C Appendix C Example 3. The only published CCM vector with an 8-byte tag, and it carries
 * associated data, which the peripheral's streaming API has no way to accept: a test reaches it through
 * hal_host_aes_ccm_aad(). */
static const aes_ccm_kat_t AES_CCM_SPEC[] = {
  {.key = "404142434445464748494a4b4c4d4e4f", .nonce = "101112131415161718191a1b", .aad = "000102030405060708090a0b0c0d0e0f10111213", .plaintext = "202122232425262728292a2b2c2d2e2f3031323334353637", .out = "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"}
};

#define AES_CCM_SPEC_COUNT (sizeof(AES_CCM_SPEC) / sizeof(AES_CCM_SPEC[0]))

/* What the device asks for: no associated data, nonce 13, tag 8. */
static const aes_ccm_kat_t AES_CCM_DEVICE[] = {
  {.key = "00112233445566778899aabbccddeeff", .nonce = "000102030405060708090a0b0c", .aad = "", .plaintext = "", .out = "2b58a02b44f403a8"},
  {.key = "404142434445464748494a4b4c4d4e4f", .nonce = "101112131415161718191a1b1c", .aad = "", .plaintext = "03", .out = "4a6ac8dcd12d212072"},
  {.key = "000102030405060708090a0b0c0d0e0f", .nonce = "f0e1d2c3b4a5968778695a4b3c", .aad = "", .plaintext = "030a11181f262d", .out = "efe959294bc507cd67e78c01cbf4f6"},
  {.key = "6c79b4d5a342ae0f8c38f73f44e52b7e", .nonce = "11223344556677889900aabbcc", .aad = "", .plaintext = "030a11181f262d343b424950575e65", .out = "b41a71bc55373004bd59169a7d042f9b7ba37172fc26c1"},
  {.key = "00000000000000000000000000000000", .nonce = "00000000000000000000000000", .aad = "", .plaintext = "030a11181f262d343b424950575e656c", .out = "d672e3151fb3a1586b2c7f26c9f3ab020e6519b434df05a8"},
  {.key = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", .nonce = "0123456789abcdeffedcba9876", .aad = "", .plaintext = "030a11181f262d343b424950575e656c73", .out = "493276ba06becbb98bfaabfd237357564847b963a32dda52eb"},
  {.key = "9e88e9f2d9e0b5dac1d2e3f4a5b6c7d8", .nonce = "0a0b0c0d0e0f10111213141516", .aad = "", .plaintext = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5", .out = "da4f043a832246383848f8976f52b0394a5ba6e4ec71f6869a5e57cc4dbc93a1c01c9822ac3560"},
  {.key = "0123456789abcdeffedcba9876543210", .nonce = "1d4e7a2b3c5d6e7f8091a2b3c4", .aad = "", .plaintext = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc", .out = "d0d8b987c164801e76676d81409e3c3aa8dad81e666f1cf46aaf185d86f6706f92ef4a5adc14a87e"},
  {.key = "11111111111111111111111111111111", .nonce = "ffffffffffffffffffffffffff", .aad = "", .plaintext = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3", .out = "51bcd36341e81f506df3ada7dfa34314ba4b23b1a1c95e550f4ca87b31a69c68e20e932e7597971e06"},
  {.key = "5b6c7d8e9f001122334455667788990a", .nonce = "7a6b5c4d3e2f1001a2b3c4d5e6", .aad = "", .plaintext = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e45", .out = "5afe68141f0afa67c267bdc8b6b73e25753e60d800f0ca943489ce6ed6f4c044ffb7f5e95131b84301b34f539bc39a5bd9ac8afce0faff"},
  {.key = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", .nonce = "0f1e2d3c4b5a69788796a5b4c3", .aad = "", .plaintext = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc", .out = "6a4364d6d0212efd686e495f42caeaa6313e180bfe1b8964838b8bb7a94cd00eb20b859787003eb4f2ffec2b7c29edd6a40d132cac35ca853a96be28b59a06cb3d388003448da8ac"},
  {.key = "3c4d5e6f708192a3b4c5d6e7f8091a2b", .nonce = "5a4b3c2d1e0f00112233445566", .aad = "", .plaintext = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d54", .out = "8ca175c395fa81ce602a6492d3993d9ef10337f4221a806c94a46cabc809b77039e956494591baefd4965a51b70f5163fe37062bcc895e422dbc338f0029240b7888537aad34fa39c31e9d914d61611dfb2a5aa825b67703f8fe5d7f8349745d35e4b127888d10db213563c0ac4cfceb54a494557fa7d55a44cc2a5a1866bf1a6df879506384ec342800f8bc6994c40b21083cded360dd064891ed939d1ab6cbbe8b4b7d988ecb00be966242368c86db04ad7888d54179fb3c3131e3c7b7de42028562586d7e7d22c67c4338bcca3c710de5a31e34feff1ef299867260d2644aed88c356584736c7a3a26cc28acca96b7dd98d026dac2ad5b322c926b95de69df0e948f62661c9d2c073989a3b4965f9d2acd6dc177b7d599b32926379db85599bd5f274484b8678a930c5a0ae6006cadb034038334b7757b6d888d66b4fec2c8457383a43b258c8cdcc3ae147b4cbdc6c5c4792c06e852d4c6338790a2f788486c7b8caa8bf412a9431cac3e93dbf86b5123cb0b0b30a62a3c64fb75119c649e4616a401764ed5c28e4c6f54fb6a4ff1e62a6994ba15f79c88311b85fb8aa4c3973b46c0d64db52699fde7ae5ffb7c161eb96b1956109c6589bde7e21664b11103e080e283e568296c3377aea71629b810300d1b3d98a71eaebef41089357201d043bb5e37aa57c86dee1b618cf6f1b98a5598210a29236236e2ab9603fdc1ab38a8bc80691b325111df3e093501cc9948ee462a1f058f615b9bc96deac3e2ba9bb7026611ecd43a8a256253dcc61c33e879c71e47d78b827a10edb8e6f8b3c26db717c355e3e93a89f0a1cde66a7c8084e573d8190e9149d403365e68d638a0dc5d3f0629c9770e935f95da1c175a5178a3ad3abb5144605ef46393a5795faf44f31148e81a991175c6b9efbcb3e620bea7404cd50dac9263918bf10559d92c2ad2209041bb05f853d782a55b7587140eff5d9e13347d159773f962fd1a2039685ddea9de6e747003eabf8beba4f0a9449f60dcb396b544ad1861bc07c90063d11c24053188d86ed1d18afa7e30be0fc414c0618383f09f5599500cc44c919d29c8f4f87301821f091fd30490e788040f136353773db49e85762a205d5c029380a1741a4961e1dec946d3b6233df21136a255d16a1c0b2124b7d489282b376433e8cee69fc9345ffa34d862908f908854e1e2385533145d66c2d108a72d9b6341595ea7e56b26ba82878578e703c4aa51d11cefceac2ef24452a0cbcdc74420f48d6dd06df2351afc619a695914d65ba2117010425951588892de6dd8d68c9c34b9efdc9cb7558b31fb4727761ca33d244be0dcd40d25c640b67b25a516af11e1613f3d73b12122e0b9c8b2cb1544702bbe6d56513a1cfe3c863666f068eb2c868c20cefb41eaaab360ae844a27811"}
};

#define AES_CCM_DEVICE_COUNT (sizeof(AES_CCM_DEVICE) / sizeof(AES_CCM_DEVICE[0]))

typedef struct {
  const char* key;
  const char* iv;
  const char* data;
  const char* out;
} aes_cbc_kat_t;

/* reference: pycryptodome's AES-256-CBC, independent of the model in host/hal_aes_host.c. There is no
 * published AES-256 CBC vector set: SP 800-38A's examples and RFC 3602 are both 128-bit only. */
static const aes_cbc_kat_t AES_CBC_KAT[] = {
  {.key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", .iv = "000102030405060708090a0b0c0d0e0f", .data = "05121f2c394653606d7a8794a1aebbc8", .out = "0f47cc891d08738b4fcf23544c463dc3"},
  {.key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", .iv = "ffffffffffffffffffffffffffffffff", .data = "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98", .out = "01dc440d0f8e85a12bfa5a2b6939a0768a97d0ac48c0c479dada7af8385acdef"},
  {.key = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", .iv = "101112131415161718191a1b1c1d1e1f", .data = "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b68", .out = "d7ff3ccf7ff44fc9667f6e95758a35d2196c7e658969d72c1e2235ef16d98ed1404c0d5dd4e728360997b057ec1bebc0"},
  {.key = "0000000000000000000000000000000000000000000000000000000000000000", .iv = "00000000000000000000000000000000", .data = "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b38", .out = "412ec600c96919965473a99c14a6530baff41053ac3b8a014659282984a9b050a8df6ce90ecb85457e1410e31d17a1e6ff32e2ad8c5f985e4f2d00970df3d193"}
};

#define AES_CBC_KAT_COUNT (sizeof(AES_CBC_KAT) / sizeof(AES_CBC_KAT[0]))

/* aes_cbc_mac() is CBC with a zero IV, read back as the last block. Lengths are multiples of the block:
 * the function rounds up, so anything else would drag in whatever follows the message. */
static const aes_cbc_kat_t AES_CBC_MAC_KAT[] = {
  {.key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", .iv = "", .data = "0b2845627f9cb9d6f3102d4a6784a1be", .out = "172f086335c0ae3781c6af5395bfc828"},
  {.key = "0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0", .iv = "", .data = "0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718e", .out = "2671d24074a22352ad76a5219a4eac75"},
  {.key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .iv = "", .data = "0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e", .out = "2619cfe47544497751ec4fe26e5750f6"}
};

#define AES_CBC_MAC_KAT_COUNT (sizeof(AES_CBC_MAC_KAT) / sizeof(AES_CBC_MAC_KAT[0]))

#endif
