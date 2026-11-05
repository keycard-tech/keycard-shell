#ifndef VECTORS_BIP32_H
#define VECTORS_BIP32_H

/* spec: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki
 * sha256 e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f
 * reference: coincurve expands each published key to the uncompressed form the code works in
 *
 * Two consecutive xpubs of one test chain, where the child's number has the hardened bit clear,
 * are a public derivation the standard defines: parent key, parent chain code, index, child key
 * and child chain code all come out of the document. The hardened rows are the same parents asked
 * for with the hardened bit set, which is the one input the code is told to refuse; BIP-32
 * publishes nothing to compare against there, so those rows claim only that no key comes out.
 */
typedef struct {
  const char* path;
  const char* parent_pub;
  const char* parent_chain;
  unsigned index;
  const char* child_pub; /* empty when ok is 0 */
  const char* child_chain;
  int ok;
} bip32_ckd_t;

static const bip32_ckd_t BIP32_CKD[] = {
  {"m/0H/1", "045a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc567f717885be239daadce76b568958305183ad616ff74ed4dc219a74c26d35f839", "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", 1U, "04501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c008794c1df8131b9ad1e1359965b3f3ee2feef0866be693729772be14be881ab", "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", 1},
  {"m/0H/1/2H/2", "0457bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc24310ef3676384179e713be3115e93f34ac9a3933f6367aeb3081527ea74027b7", "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f", 2U, "04e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d292728ad8d58a140050c1016e21f285636a580f4d2711b7fac3957a594ddf416a0", "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", 1},
  {"m/0H/1/2H/2/1000000000", "04e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d292728ad8d58a140050c1016e21f285636a580f4d2711b7fac3957a594ddf416a0", "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", 1000000000U, "042a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011cf31cb47de7ccf6196d3a580d055837de7aa374e28c6c8a263e7b4512ceee362", "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e", 1},
  {"m/0", "04cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a77bd3305d363c26f82c1e41c667e4b3561c06c60a2104d2b548e6dd059056aa51", "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689", 0U, "04fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea67a50538b6f7d8b5f7a1cc657efd267cde8cc1d8c0451d1340a0fb3642777544", "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c", 1},
  {"m/0/2147483647H/1", "04c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b6c8bf5e8fbfc053205b45776963d148187d0aebf9c08bf2b253dc1cf5860fc19", "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9", 1U, "04a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9105b3150817d235e80ea17914dc9d6f542b1c5f4b16d8d98fe3c94fc0a67de89", "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb", 1},
  {"m/0/2147483647H/1/2147483646H/2", "04d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0ecb53a1b24eda1117d6864f1dbaf2f92345a1cb52c70036e2a424b37c3d829b0", "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29", 2U, "044d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c4597bb130cb16893607c6e7418c46be47b8f4a3ddbe5e6e71051393b1d673abe", "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271", 1},
  {"m, asked for with the hardened bit set", "0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281", "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", 2147483648U, "", "", 0},
  {"m/0H/1, asked for with the hardened bit set", "04501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c008794c1df8131b9ad1e1359965b3f3ee2feef0866be693729772be14be881ab", "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", 2147483650U, "", "", 0},
  {"m/0, asked for with the hardened bit set", "04fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea67a50538b6f7d8b5f7a1cc657efd267cde8cc1d8c0451d1340a0fb3642777544", "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c", 4294967295U, "", "", 0},
  {"m/0/2147483647H/1, asked for with the hardened bit set", "04a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9105b3150817d235e80ea17914dc9d6f542b1c5f4b16d8d98fe3c94fc0a67de89", "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb", 4294967294U, "", "", 0},
  {"m, asked for with the hardened bit set", "04683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669d2f2686ced96d375a75298f07ed30751e2a3f45e2d184b268d02c8d5dd6fbdb5", "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f", 2147483648U, "", "", 0},
  {"m, asked for with the hardened bit set", "046f6fedc9240f61daa9c7144b682a430a3a1366576f840bf2d070101fcbc9a02d64f0ba4512324da4cb12cd1b7b09a3410ad2e88fa9c51067528b4a21edd1c820", "d0c8a1f6edf2500798c3e0b54f1b56e45f6d03e6076abd36e5e2f54101e44ce6", 2147483648U, "", "", 0},
  {"m/0H, asked for with the hardened bit set", "049382d2b6003446792d2917f7ac4b3edf079a1a94dd4eb010dc25109dda680a9d2ea33616de0b194f4c2a246ecefaff985c15671b7600d9d06ba4d658a280a1a7", "cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b", 2147483649U, "", "", 0}
};

#define BIP32_CKD_COUNT (sizeof(BIP32_CKD) / sizeof(BIP32_CKD[0]))

/* The same published chain walked through the account context: setup at the account level, then
 * the change level, then a leaf. The leaf is compared as the document writes it, compressed,
 * because that is the form the context hands to the address encoders. */
typedef struct {
  const char* account_path;
  const char* account_pub;
  const char* account_chain;
  unsigned change;
  unsigned leaf;
  const char* change_pub;
  const char* change_chain;
  const char* leaf_pub;
} bip32_walk_t;

static const bip32_walk_t BIP32_WALK[] = {
  {"m/0H/1/2H", "0457bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc24310ef3676384179e713be3115e93f34ac9a3933f6367aeb3081527ea74027b7", "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f", 2U, 1000000000U, "04e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d292728ad8d58a140050c1016e21f285636a580f4d2711b7fac3957a594ddf416a0", "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"}
};

#define BIP32_WALK_COUNT (sizeof(BIP32_WALK) / sizeof(BIP32_WALK[0]))

#endif /* VECTORS_BIP32_H */
