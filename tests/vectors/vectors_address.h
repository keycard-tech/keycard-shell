#ifndef VECTORS_ADDRESS_H
#define VECTORS_ADDRESS_H

/* reference: eth_utils.to_checksum_address (EIP-55) and coincurve/libsecp256k1 point
 * decompression, applied to the public keys inside https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki
 * sha256 e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f
 *
 * eth_address is the 20 raw bytes without 0x; eth_address_checksummed is the EIP-55
 * mixed-case rendering, also without 0x.
 */
typedef struct {
  const char* pubkey_compressed;
  const char* pubkey_uncompressed; /* 0x04 || x || y */
  const char* eth_address;
  const char* eth_address_checksummed;
} eth_address_vector_t;

static const eth_address_vector_t ETH_ADDRESS_VECTORS[] = {
  {"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2", "0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281", "056db290f8ba3250ca64a45d16284d04bc6f5fbf", "056DB290F8Ba3250ca64a45D16284D04Bc6f5FBf"},
  {"035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56", "045a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc567f717885be239daadce76b568958305183ad616ff74ed4dc219a74c26d35f839", "bf6e48966d0dcf553b53e7b56cb2e0e72dca9e19", "BF6e48966d0dcf553b53e7b56CB2e0E72dca9E19"},
  {"03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c", "04501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c008794c1df8131b9ad1e1359965b3f3ee2feef0866be693729772be14be881ab", "29379f45f515c494483298225d1b347f73d1babf", "29379f45F515C494483298225d1B347F73D1babF"},
  {"0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2", "0457bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc24310ef3676384179e713be3115e93f34ac9a3933f6367aeb3081527ea74027b7", "d8e85fbbb4b3b3c71c4e63a5580d0c12fb4d2f71", "d8e85FBbb4b3b3c71C4e63A5580d0c12fb4D2f71"}
};

#define ETH_ADDRESS_VECTOR_COUNT (sizeof(ETH_ADDRESS_VECTORS) / sizeof(ETH_ADDRESS_VECTORS[0]))

/* spec: https://raw.githubusercontent.com/ethereum/ercs/master/ERCS/erc-55.md
 * sha256 54a9b25ffcd12966c60d6abd6584734d2793734f266fbe41118e6ee52b05dc9e
 *
 * The addresses the checksum document publishes. `lower` is those same bytes in the form the
 * document says carries no checksum, `mixed` the form that does, so a row pins both the encoder
 * and what the verifier must accept.
 */
typedef struct {
  const char* lower;
  const char* mixed;
} erc55_vector_t;

static const erc55_vector_t ERC55_VECTORS[] = {
  {"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
  {"fb6916095ca1df60bb79ce92ce3ea74c37c5d359", "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
  {"dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb", "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
  {"d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb", "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
  {"52908400098527886e0f7030069857d2e4169ee7", "52908400098527886E0F7030069857D2E4169EE7"},
  {"8617e340b3d01fa5f11f306f4090fd50e238070d", "8617E340B3D01FA5F11F306F4090FD50E238070D"},
  {"de709f2102306220921060314715629080e2fb77", "de709f2102306220921060314715629080e2fb77"},
  {"27b1fdb04752bbc536007a920d24acb045561c26", "27b1fdb04752bbc536007a920d24acb045561c26"}
};

#define ERC55_VECTOR_COUNT (sizeof(ERC55_VECTORS) / sizeof(ERC55_VECTORS[0]))

/* The version bytes of https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki
 * sha256 e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f's own keys for the 4 byte cases, the
 * boundaries of address_prefix_bytes_len() for the rest. `bytes` is the version written
 * big-endian over exactly `len` bytes, which is what address_check_prefix() reads back.
 */
typedef struct {
  uint32_t version;
  unsigned char len;
  const char* bytes;
} addr_prefix_vector_t;

static const addr_prefix_vector_t ADDR_PREFIX_VECTORS[] = {
  {0x00000000, 1, "00"},
  {0x00000001, 1, "01"},
  {0x0000007F, 1, "7f"},
  {0x00000080, 1, "80"},
  {0x000000FF, 1, "ff"},
  {0x00000100, 2, "0100"},
  {0x0000FFFF, 2, "ffff"},
  {0x00010000, 3, "010000"},
  {0x00FFFFFF, 3, "ffffff"},
  {0x01000000, 4, "01000000"},
  {0x7FFFFFFF, 4, "7fffffff"},
  {0xFFFFFFFF, 4, "ffffffff"},
  {0x0488ADE4, 4, "0488ade4"},
  {0x0488B21E, 4, "0488b21e"}
};

#define ADDR_PREFIX_VECTOR_COUNT (sizeof(ADDR_PREFIX_VECTORS) / sizeof(ADDR_PREFIX_VECTORS[0]))

#endif
