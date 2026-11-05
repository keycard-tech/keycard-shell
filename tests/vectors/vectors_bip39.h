#ifndef VECTORS_BIP39_H
#define VECTORS_BIP39_H

/* spec: https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json
 * sha256 fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8
 *
 * One entry per official BIP-39 English vector: entropy, mnemonic, PBKDF2-HMAC-SHA512
 * seed (2048 rounds, salt "mnemonic" + passphrase "TREZOR"), and the same mnemonic with
 * its last word replaced by a different real word that must fail the checksum.
 *
 * supported is true for the entropy lengths this firmware implements (12 and 24 words);
 * the official vectors also cover 15, 18 and 21 word mnemonics.
 */
#include <stdbool.h>

typedef struct {
  const char* entropy;
  const char* mnemonic;
  const char* seed;
  const char* corrupt_mnemonic;
  bool supported;
} bip39_vector_t;

static const bip39_vector_t BIP39_VECTORS[] = {
  {"00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", true},
  {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow", "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607", "legal winner thank year wave sausage worth useful legal winner thank abandon", true},
  {"80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8", "letter advice cage absurd amount doctor acoustic avoid letter advice cage abandon", true},
  {"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abandon", true},
  {"000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent", "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", false},
  {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will", "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal abandon", false},
  {"808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always", "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter abandon", false},
  {"ffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when", "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abandon", false},
  {"0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", true},
  {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth abandon", true},
  {"8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless", "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic abandon", true},
  {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abandon", true},
  {"9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic", "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028", "ozone drill grab fiber curtain grace pudding thank cruise elder eight abandon", true},
  {"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b", "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog", "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac", "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow abandon", false},
  {"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length", "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay abandon", true},
  {"c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow", "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612", "scheme spot photo card baby mountain device kick cradle pact join abandon", true},
  {"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave", "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d", "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack abandon", false},
  {"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside", "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost abandon", true},
  {"23db8160a31d3e0dca3688ed941adbf3", "cat swing flag economy stadium alone churn speed unique patch report train", "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5", "cat swing flag economy stadium alone churn speed unique patch report abandon", true},
  {"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access", "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02", "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud abandon", false},
  {"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform", "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt abandon", true},
  {"f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture", "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f", "vessel ladder alter error federal sibling chat ability sun glass valve abandon", true},
  {"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump", "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88", "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress abandon", false},
  {"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold", "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve abandon", true}
};

#define BIP39_VECTOR_COUNT (sizeof(BIP39_VECTORS) / sizeof(BIP39_VECTORS[0]))

/* spec: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
 * sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
 *
 * Digest of the official list joined by '
' with a trailing newline.
 */
#define BIP39_WORDLIST_COUNT 2048
#define BIP39_WORDLIST_SHA256 "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

/* spec: SeedQR standard mode (four decimal digits per BIP-39 index, no separator, 48 or 96 of them)
 *       and the Trezor vectors above.
 *
 * A standard SeedQR is the word indexes written as four decimal digits each, so the digit string of a
 * published mnemonic is published data too: the rows with a seed are that string, and the seed is the
 * published one. digits/len is what a caller hands over (len is separate because a scanned QR is not
 * NUL-terminated and an embedded NUL is one of the cases); indexes is a row of SEEDQR_INDEXES, or -1
 * when the string must be refused; seed is the published seed those indexes must produce under the
 * passphrase the vectors use, or NULL for the strings that are not published mnemonics.
 *
 * The rows without a seed are what the function accepts or refuses for its own reasons. Two of its
 * properties are surprising and are pinned rather than fixed:
 *
 *   - it checks the *value*, not the character class: 1000*(c-'0') is arithmetic on whatever octet is
 *     there, so ':' is 10 and 'A' in the hundreds place is 1700, and both are in range. SeedQR from a
 *     QR reader arrives as NUMERIC data, so a real scanner cannot send that; the row is here because
 *     the function is public and the next caller may not have a scanner in front of it.
 *   - *out_len is written before the digits are examined, so a refusal part way through still reports
 *     a word count. The one caller in the firmware only reads it when the answer was true.
 */
typedef struct {
  const char* digits;
  uint32_t len;
  int16_t indexes;
  const char* seed;
} seedqr_row_t;

static const uint16_t SEEDQR_INDEXES[][24] = {
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0003, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x077f, 0x03fb, 0x07df, 0x06fe, 0x07f8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0080, 0x0404, 0x0020, 0x0101, 0x0004, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07f5, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0066 },
{ 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x077f, 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x077f, 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x0717 },
{ 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0080, 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0080, 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x00bd },
{ 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07af },
{ 0x04f4, 0x0217, 0x032a, 0x02ad, 0x01b1, 0x032b, 0x0569, 0x06fe, 0x01a5, 0x023a, 0x0237, 0x0521, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0345, 0x01e7, 0x0559, 0x0223, 0x0124, 0x01cf, 0x0559, 0x0450, 0x065c, 0x071b, 0x0595, 0x00cc, 0x0347, 0x0297, 0x0326, 0x06f9, 0x043c, 0x01f1, 0x0418, 0x07eb, 0x063a, 0x039b, 0x01cf, 0x0400 },
{ 0x0605, 0x0696, 0x051d, 0x0114, 0x0088, 0x0484, 0x01e5, 0x03d1, 0x018f, 0x04f5, 0x03c1, 0x00d0, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x04fb, 0x028a, 0x00f1, 0x0325, 0x0103, 0x0666, 0x0489, 0x06f1, 0x045e, 0x01f7, 0x0672, 0x04e7, 0x0030, 0x0688, 0x049a, 0x02c3, 0x01e6, 0x0405, 0x0362, 0x057d, 0x03a3, 0x021a, 0x030c, 0x03a9 },
{ 0x011e, 0x06e0, 0x02c1, 0x0231, 0x069f, 0x0037, 0x0146, 0x0688, 0x076c, 0x0506, 0x05b7, 0x0738, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0033, 0x0372, 0x0434, 0x02bb, 0x03f4, 0x0287, 0x0365, 0x0032, 0x00a4, 0x033a, 0x0326, 0x03ee, 0x0507, 0x04eb, 0x012a, 0x048d, 0x03c9, 0x0444, 0x05b3, 0x0295, 0x064a, 0x001f, 0x05f5, 0x05a2 },
{ 0x0798, 0x03e3, 0x003b, 0x0266, 0x02a3, 0x063d, 0x0136, 0x0001, 0x06ca, 0x0317, 0x0788, 0x0522, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x07ac, 0x0170, 0x0235, 0x06c5, 0x0106, 0x06d5, 0x07ba, 0x0353, 0x0634, 0x0555, 0x0164, 0x01a8, 0x04d9, 0x003e, 0x060c, 0x0509, 0x0337, 0x0682, 0x053a, 0x06f7, 0x027e, 0x0662, 0x03b1, 0x0769 },
{ 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0384, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x03e8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x06a4, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x005a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0064, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x00aa, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x01ea, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x02e4, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0009, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x000a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0011, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0031, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x004a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 }
};

static const seedqr_row_t SEEDQR_ROWS[] = {
  {"000000000000000000000000000000000000000000000003", 48, 0, "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
  {"101920151790203919831533203119191019201517902040", 48, 1, "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"},
  {"102800320257000800640514001601281028003202570004", 48, 2, "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"},
  {"204720472047204720472047204720472047204720472037", 48, 3, "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"},
  {"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000102", 96, 4, "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"},
  {"101920151790203919831533203119191019201517902039198315332031191910192015179020391983153320311815", 96, 5, "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"},
  {"102800320257000800640514001601281028003202570008006405140016012810280032025700080064051400160189", 96, 6, "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"},
  {"204720472047204720472047204720472047204720472047204720472047204720472047204720472047204720471967", 96, 7, "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"},
  {"126805350810068504330811138517900421057005671313", 48, 8, "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028"},
  {"083704871369054702920463136911041628181914290204083906630806178510840497104820271594092304631024", 96, 9, "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"},
  {"154116861309027601361156048509770399126909610208", 48, 10, "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612"},
  {"127506500241080502591638116117771118050316501255004816721178070704861029086614050931053807800937", 96, 11, "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d"},
  {"028617600705056116950055032616721900128614631848", 48, 12, "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5"},
  {"005108821076069910120647086900500164082608061006128712590298116509691092145906611610003115251442", 96, 13, "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d"},
  {"194409950059061406751597031000011738079119281314", 48, 14, "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f"},
  {"196403680565173302621749197808511588136503560424124100621548128908231666133817830638163409451897", 96, 15, "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"},
  {"204720472047204720472047204720472047204720472047", 48, 16, ""},
  {"204800000000000000000000000000000000000000000000", 48, -1, ""},
  {"000000000000000000000000000000000000000000002048", 48, -1, ""},
  {"", 0, -1, ""},
  {"0", 1, -1, ""},
  {"00000000000000000000000000000000000000000000000", 47, -1, ""},
  {"0000000000000000000000000000000000000000000000000", 49, -1, ""},
  {"000000000000000000000000000000000000000000000000000000000000000000000000", 72, -1, ""},
  {"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 95, -1, ""},
  {"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 97, -1, ""},
  {"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 132, -1, ""},
  {"000000000000000000000000000000000000000000000000" "\000", 49, -1, ""},
  {"\000" "00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"000" "\000" "00000000000000000000000000000000000000000000", 48, -1, ""},
  {"000000000000000000000000000000000000000000000000", 48, 17, ""},
  {"900000000000000000000000000000000000000000000000", 48, -1, ""},
  {":00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"/00000000000000000000000000000000000000000000000", 48, -1, ""},
  {" 00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"-00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"A00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"a00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"z00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"\200" "00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"\377" "00000000000000000000000000000000000000000000000", 48, -1, ""},
  {"000000000000000000000000000000000000000000000000", 48, 18, ""},
  {"090000000000000000000000000000000000000000000000", 48, 19, ""},
  {"0:0000000000000000000000000000000000000000000000", 48, 20, ""},
  {"0/0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"0 0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"0-0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"0A0000000000000000000000000000000000000000000000", 48, 21, ""},
  {"0a0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"0z0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"0" "\200" "0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"0" "\377" "0000000000000000000000000000000000000000000000", 48, -1, ""},
  {"000000000000000000000000000000000000000000000000", 48, 22, ""},
  {"009000000000000000000000000000000000000000000000", 48, 23, ""},
  {"00:000000000000000000000000000000000000000000000", 48, 24, ""},
  {"00/000000000000000000000000000000000000000000000", 48, -1, ""},
  {"00 000000000000000000000000000000000000000000000", 48, -1, ""},
  {"00-000000000000000000000000000000000000000000000", 48, -1, ""},
  {"00A000000000000000000000000000000000000000000000", 48, 25, ""},
  {"00a000000000000000000000000000000000000000000000", 48, 26, ""},
  {"00z000000000000000000000000000000000000000000000", 48, 27, ""},
  {"00" "\200" "000000000000000000000000000000000000000000000", 48, -1, ""},
  {"00" "\377" "000000000000000000000000000000000000000000000", 48, -1, ""},
  {"000000000000000000000000000000000000000000000000", 48, 28, ""},
  {"000900000000000000000000000000000000000000000000", 48, 29, ""},
  {"000:00000000000000000000000000000000000000000000", 48, 30, ""},
  {"000/00000000000000000000000000000000000000000000", 48, -1, ""},
  {"000 00000000000000000000000000000000000000000000", 48, -1, ""},
  {"000-00000000000000000000000000000000000000000000", 48, -1, ""},
  {"000A00000000000000000000000000000000000000000000", 48, 31, ""},
  {"000a00000000000000000000000000000000000000000000", 48, 32, ""},
  {"000z00000000000000000000000000000000000000000000", 48, 33, ""},
  {"000" "\200" "00000000000000000000000000000000000000000000", 48, -1, ""},
  {"000" "\377" "00000000000000000000000000000000000000000000", 48, -1, ""}
};

#define SEEDQR_ROW_COUNT (sizeof(SEEDQR_ROWS) / sizeof(SEEDQR_ROWS[0]))

/* spec: BIP-39's checksum (SHA-256 of the entropy, its first len/3 bits appended to the 11 bit word
 *       indexes) -- the same rule the vectors above were built with.
 *
 * The last word of a mnemonic is the only one the checksum constrains, so the words that could
 * complete a partially entered seed are computable from the words already there: the firmware does
 * that when the user has typed or scanned all but the last. indexes is a row of
 * LAST_WORD_INDEXES -- the published mnemonic minus its last word -- last is the published last word,
 * count is the number of completions (2 to the power of the bits the last word does not carry), and
 * mask_sha256 is the digest of the 256 byte candidate bitmap in index order.
 */
typedef struct {
  uint32_t words;
  uint16_t last;
  uint32_t count;
  const char* mask_sha256;
} last_word_row_t;

static const uint16_t LAST_WORD_INDEXES[][24] = {
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x077f, 0x03fb, 0x07df, 0x06fe, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0080, 0x0404, 0x0020, 0x0101, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x077f, 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x077f, 0x03fb, 0x07df, 0x06fe, 0x07f7, 0x07bf, 0x05fd, 0x07ef, 0x0000 },
{ 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0080, 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0080, 0x0404, 0x0020, 0x0101, 0x0008, 0x0040, 0x0202, 0x0010, 0x0000 },
{ 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x07ff, 0x0000 },
{ 0x04f4, 0x0217, 0x032a, 0x02ad, 0x01b1, 0x032b, 0x0569, 0x06fe, 0x01a5, 0x023a, 0x0237, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0345, 0x01e7, 0x0559, 0x0223, 0x0124, 0x01cf, 0x0559, 0x0450, 0x065c, 0x071b, 0x0595, 0x00cc, 0x0347, 0x0297, 0x0326, 0x06f9, 0x043c, 0x01f1, 0x0418, 0x07eb, 0x063a, 0x039b, 0x01cf, 0x0000 },
{ 0x0605, 0x0696, 0x051d, 0x0114, 0x0088, 0x0484, 0x01e5, 0x03d1, 0x018f, 0x04f5, 0x03c1, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x04fb, 0x028a, 0x00f1, 0x0325, 0x0103, 0x0666, 0x0489, 0x06f1, 0x045e, 0x01f7, 0x0672, 0x04e7, 0x0030, 0x0688, 0x049a, 0x02c3, 0x01e6, 0x0405, 0x0362, 0x057d, 0x03a3, 0x021a, 0x030c, 0x0000 },
{ 0x011e, 0x06e0, 0x02c1, 0x0231, 0x069f, 0x0037, 0x0146, 0x0688, 0x076c, 0x0506, 0x05b7, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x0033, 0x0372, 0x0434, 0x02bb, 0x03f4, 0x0287, 0x0365, 0x0032, 0x00a4, 0x033a, 0x0326, 0x03ee, 0x0507, 0x04eb, 0x012a, 0x048d, 0x03c9, 0x0444, 0x05b3, 0x0295, 0x064a, 0x001f, 0x05f5, 0x0000 },
{ 0x0798, 0x03e3, 0x003b, 0x0266, 0x02a3, 0x063d, 0x0136, 0x0001, 0x06ca, 0x0317, 0x0788, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000 },
{ 0x07ac, 0x0170, 0x0235, 0x06c5, 0x0106, 0x06d5, 0x07ba, 0x0353, 0x0634, 0x0555, 0x0164, 0x01a8, 0x04d9, 0x003e, 0x060c, 0x0509, 0x0337, 0x0682, 0x053a, 0x06f7, 0x027e, 0x0662, 0x03b1, 0x0000 }
};

static const last_word_row_t LAST_WORD_ROWS[] = {
  {12, 0x0003, 128, "e109dd05e2f5d2b502c5309d481b0a66e808c8ec49e9a124649e993bf528c3ed"},
  {12, 0x07f8, 128, "5f05dca74aee630413326e1b51eb0164886edf0cf337daba17ea3bcf875fbb15"},
  {12, 0x0004, 128, "ffb52621700d457086fd403cbb0b713af0e5c07b0e41a924153b8801db846d8c"},
  {12, 0x07f5, 128, "128e91e1f2878a13faafad9dbc1b5d09f2dcb0ff2f118405b72743cd74d129ad"},
  {24, 0x0066, 8, "6bf2cfe59fc32bb6c4378eec0516b8bad38dd557f3600d70cb7139829a365f37"},
  {24, 0x0717, 8, "9b0a8aa7805e77aec0ab7483ee752f1dcd1075488f2f0c3948397cb91288cf4d"},
  {24, 0x00bd, 8, "d94b9f4af57f0fa01f690128ebd3ed83dff263174759fcd66de86abb86741bfc"},
  {24, 0x07af, 8, "b1c86360e22aa11d12ddf7115771127e656d9c6243fd25b26f35a15f213aefe8"},
  {12, 0x0521, 128, "59e02d7de41d2aa4e952d2bec29a8f8eac07a7037cb4d107c775cc6aafdf9db6"},
  {24, 0x0400, 8, "fe0dfe69ef49da4969de0697719370c11d9a63d31813a692c66b634761c8046b"},
  {12, 0x00d0, 128, "36668e3827b103a7bdee97dd58b21b271a67affd8cb761d929c12e175c832d79"},
  {24, 0x03a9, 8, "3257bc2ce2cacc0ab84ed693c7ba1d8677a82b06bbeb900bb3c75be24d903974"},
  {12, 0x0738, 128, "f02b706a23c6afb1fe61a5336f4220caf70b92261f07251a20f32b5d9dd32e36"},
  {24, 0x05a2, 8, "e9746bd3f244c5e054c5fa920ed15697c8ec848ef654ced1f018c9a315240fdb"},
  {12, 0x0522, 128, "d4df764657abb0e89959347e57a902e3efb237ae16563f259424376ad12d5f19"},
  {24, 0x0769, 8, "302ee3ac23cdcb6b9ee8c4a877bc0f00ea4f5276f8ed60bbf1df8698dd89db05"}
};

#define LAST_WORD_ROW_COUNT (sizeof(LAST_WORD_ROWS) / sizeof(LAST_WORD_ROWS[0]))

#endif
