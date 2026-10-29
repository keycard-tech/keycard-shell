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

#endif
