#ifndef VECTORS_BECH32_H
#define VECTORS_BECH32_H

/* spec: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0173.mediawiki
 * sha256 b19eab06b264bbd15ad7f7d640fa34de8f4a8809fba8a6ecc3e165545b27a543
 *         https://raw.githubusercontent.com/bitcoin/bips/master/bip-0350.mediawiki
 * sha256 63634b06aa8bae88b31929674736e74964c4598684269ac2b0b140c43a7a0dec
 *
 * witness_program_t is the decoded form segwit_addr_decode() must return for the address;
 * the same rows drive the encoder in the other direction. Upper-case rows check that the
 * encoder accepts a mixed-case address, as the spec requires.
 *
 * The invalid rows are the ones each document lists as rejected for the mainnet prefix,
 * so they are all decoded with "bc" -- including the row whose stated reason is a wrong
 * human-readable part.
 */
#define SEGWIT_HRP "bc"

typedef struct {
  const char* address;
  const char* hrp;
  int witver;
  const char* program;
} witness_program_t;

static const witness_program_t BECH32_VALID[] = {
  {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc", 0, "751e76e8199196d454941c45d1b3a323f1433bd6"},
  {"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "tb", 0, "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
  {"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "tb", 0, "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"}
};

#define BECH32_VALID_COUNT (sizeof(BECH32_VALID) / sizeof(BECH32_VALID[0]))

static const char* const BECH32_INVALID[] = {
  "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
  "pzry9x0s0muk",
  "1pzry9x0s0muk",
  "x1b4n0q5v",
  "li1dgmt3",
  "A1G7SGD8",
  "10a06t8",
  "1qzzfhee",
  "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
  "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
  "bc1rw5uspcuh",
  "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
  "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
  "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
  "bc1gmk9yu"
};

#define BECH32_INVALID_COUNT (sizeof(BECH32_INVALID) / sizeof(BECH32_INVALID[0]))

static const witness_program_t BECH32M_VALID[] = {
  {"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "bc", 1, "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
  {"BC1SW50QGDZ25J", "bc", 16, "751e"},
  {"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "bc", 2, "751e76e8199196d454941c45d1b3a323"},
  {"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "tb", 1, "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
  {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc", 1, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}
};

#define BECH32M_VALID_COUNT (sizeof(BECH32M_VALID) / sizeof(BECH32M_VALID[0]))

static const char* const BECH32M_INVALID[] = {
  "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
  "qyrz8wqd2c9m",
  "1qyrz8wqd2c9m",
  "y1b0jsk6g",
  "lt1igcx5c0",
  "in1muywd",
  "mm1crxm3i",
  "au1s5cgom",
  "M1VUXWEZ",
  "16plkw9",
  "1p2gdwpf",
  "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
  "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
  "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
  "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
  "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
  "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
  "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
  "bc1pw5dgrnzv",
  "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
  "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
  "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
  "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j"
};

#define BECH32M_INVALID_COUNT (sizeof(BECH32M_INVALID) / sizeof(BECH32M_INVALID[0]))

#endif
