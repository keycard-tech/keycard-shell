#ifndef VECTORS_BASE58_H
#define VECTORS_BASE58_H

/* spec: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki
 * sha256 e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f
 *
 * The extended keys are the official BIP-32 serialisations; the payload is everything
 * before the 4-byte double-SHA256 checksum, decoded with the BIP-13 alphabet. They carry
 * leading zero bytes, big-endian magnitude and the alphabet boundary cases.
 */
typedef struct {
  const char* encoded;
  const char* payload;
} base58_vector_t;

static const base58_vector_t BASE58_VECTORS[] = {
  {"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"},
  {"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"},
  {"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"},
  {"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"},
  {"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"},
  {"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"},
  {"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", "0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"},
  {"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"}
};

#define BASE58_VECTOR_COUNT (sizeof(BASE58_VECTORS) / sizeof(BASE58_VECTORS[0]))

/* reference: BIP-13 base58check over CPython hashlib double SHA-256. */
typedef struct {
  const char* hash160;
  unsigned char prefix;
  const char* address;
} legacy_address_vector_t;

static const legacy_address_vector_t LEGACY_ADDRESS_VECTORS[] = {
  {"3442193e1bb70916e914552172cd4e2dbc9df811", 0, "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"},
  {"3442193e1bb70916e914552172cd4e2dbc9df811", 5, "36TLF8X6MmL5bjoKqyHzNZa8A6N1dbNoZM"},
  {"6165268591d3f870de10447dba127e02ab8f29cd", 0, "19syifcmoFQSL4BFACGnarC7QnCTLYY36G"},
  {"6165268591d3f870de10447dba127e02ab8f29cd", 5, "3AZzeD7DM9ipRDsgHHwP1UZ3ZJVAvzMY7Z"},
  {"5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7", 0, "19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh"},
  {"5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7", 5, "3A63SLvXFLkUYHyApQnuyxicv2sYbNu7Fe"},
  {"ec49238f4f776bfb96a554eeafde62e56cd7bb2c", 0, "1NYN642gCYQbGkpmFaf1k9Uc4kCM263ExV"},
  {"ec49238f4f776bfb96a554eeafde62e56cd7bb2c", 5, "3PEP1bX7kSiyMvXCNgKcAmqYDGV4eMB8S3"},
  {"bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe", 0, "1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj"},
  {"bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe", 5, "3K6ia86mwXfU4buByfR5WicxKLTFCDaCUF"},
  {"f3ee6e9497f0b05865c8b2e5f04e841d5a211c1a", 0, "1PEnqA8eh5iiUBxxgm9VMZ2jZWX9GtRqJj"},
  {"f3ee6e9497f0b05865c8b2e5f04e841d5a211c1a", 5, "3Pvokhd6Ez36ZMfPorp5nBPfi2orqY5yzw"},
  {"ee7ab90cde56a8c0e2bb086ac49748b8db9dce72", 0, "1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x"},
  {"ee7ab90cde56a8c0e2bb086ac49748b8db9dce72", 5, "3PRym8eb8TqAnApG8aAeGoRAYRPsUBUiZ7"},
  {"b5087881666b2e5eb7b16473e217f26e834e8531", 0, "1HWDTH6iaXs6UdE4NtBB8D9jSHSsvETUJD"},
  {"b5087881666b2e5eb7b16473e217f26e834e8531", 5, "3JCENpbA8SBUZnvVVyqmYqWfaojbUY5qMs"}
};

#define LEGACY_ADDRESS_VECTOR_COUNT (sizeof(LEGACY_ADDRESS_VECTORS) / sizeof(LEGACY_ADDRESS_VECTORS[0]))

/* spec: https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/base58.cpp
 * sha256 c7bf90c6100c911fe4b3e1eac910475340f3e539f9e0ac793b31df3b492391be */
#define B58_ALPHABET "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

#endif
