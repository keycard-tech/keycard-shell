#ifndef VECTORS_BYTEWORDS_H
#define VECTORS_BYTEWORDS_H

/* spec: https://raw.githubusercontent.com/BlockchainCommons/bc-bytewords/master/src/bc-bytewords.c
 * sha256 6fb8827c3d56dc2c92bf42a103aa67d05809eea8be87d41449f3cfbf68f964e4
 * spec: https://raw.githubusercontent.com/BlockchainCommons/bc-bytewords/master/test/test.c
 * sha256 1cd44d351731b85a2cd49f8b47526f2fda9505cf30cead9ec05a6074d2ef15cf
 * reference: zlib.crc32 for the trailing four codes
 *
 * app/ur/bytewords.c implements bytewords minimal: two letters per byte with no separator, and
 * the CRC32 of the payload appended as four more codes. The letters are a word's first and last,
 * unique per byte, which is what makes a lone code decodable. Case is not significant to the
 * decoder; this implementation writes uppercase, the reference below writes lowercase, so compare
 * case-insensitively.
 */

/* Two letters per byte, uppercase: the whole vocabulary of the decoder, in byte order. */
#define BYTEWORDS_MINIMAL "AEADAOAXAAAHAMATAYASBKBDBNBTBABSBEBYBGBWBBBZCMCHCSCFCYCWCECACKCTCXCLCPCNDKDADSDIDEDTDRDNDWDPDMDLDYEHEYEOEEECENEMETESFTFRFNFSFMFHFZFPFWFXFYFEFGFLFDGAGEGRGSGTGLGWGDGYGMGUGHGOHFHGHDHKHTHPHHHLHYHEHNHSIDIAIEIHIYIOISINIMJEJZJNJTJLJOJSJPJKJYKPKOKTKSKKKNKGKEKIKBLBLALYLFLSLRLPLNLTLOLDLELULKLGMNMYMHMEMOMUMWMDMTMSMKNLNYNDNSNTNNNENBOYOEOTOXONOLOSPDPTPKPYPSPMPLPEPFPAPRQDQZRERPRLRORHRDRKRFRYRNRSRTSESASRSSSKSWSTSPSOSGSBSFSNTOTKTITTTDTETYTLTBTSTPTATNUYUOUTUEURVTVYVOVLVEVWVAVDVSWLWDWMWPWEWYWSWTWNWZWFWKYKYNYLYAYTZSZOZTZCZEZM"

typedef struct {
  const char* name;
  const char* payload;
  const char* encoded;
} bytewords_vector_t;

static const bytewords_vector_t BYTEWORDS_VECTORS[] = {
  { "bc-bytewords vector, 5 bytes", "00010280ff", "aeadaolazmjendeoti" },
  { "bc-bytewords vector, 100 bytes", "f5d714c6f1eb453bd1cda512969e7487e5d4139f1125eff0fd0b6dbf25f22678df299cbdf2fe93cc42a3d8afbf48a936203c90e6d289b8c52171580e9d1fb12e0173cd45e19641eb3a9041f0854571f73f35f2a5a0901a0d4fed85475245fea58a295518", "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwnebydawswtzcbdjnrsdawzdsksurdtnsrywzzemusffwottppersfdptencxfnmhvatdldroskcljshdbantctpadmadjksnfevymtfpwmftmhfpwtlpfejsylfhecwzonnbmhcybtgwwelpflgmfezeonledtgocsfzhycypf" },
  { "reference payload, 1 bytes", "0b", "bdfetienah" },
  { "reference payload, 2 bytes", "0b12", "bdbggymwrdke" },
  { "reference payload, 3 bytes", "0b1219", "bdbgcfwsluwyvt" },
  { "reference payload, 4 bytes", "0b121920", "bdbgcfcxgaldolte" },
  { "reference payload, 5 bytes", "0b12192027", "bdbgcfcxdiisndgddm" },
  { "reference payload, 31 bytes", "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dd", "bdbgcfcxdidmecfnfxgegyhdheiyjnjykglfldmhmsnnonpsqdrdsesptktbutgmosvesg" },
  { "reference payload, 32 bytes", "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4", "bdbgcfcxdidmecfnfxgegyhdheiyjnjykglfldmhmsnnonpsqdrdsesptktbutvebalnfeol" },
  { "reference payload, 33 bytes", "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4eb", "bdbgcfcxdidmecfnfxgegyhdheiyjnjykglfldmhmsnnonpsqdrdsesptktbutvewmtnhsghvw" },
  { "reference payload, 64 bytes", "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4", "bdbgcfcxdidmecfnfxgegyhdheiyjnjykglfldmhmsnnonpsqdrdsesptktbutvewmwzytaeatbabzcecndrehetfhfggtghhpidinjoktkblplkmunyoypdperpryssdkptwlox" },
  { "reference payload, 129 bytes", "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b", "bdbgcfcxdidmecfnfxgegyhdheiyjnjykglfldmhmsnnonpsqdrdsesptktbutvewmwzytaeatbabzcecndrehetfhfggtghhpidinjoktkblplkmunyoypdperprysssbtdtavtvdwyykztaxbkbycsctdsdpeefrfwgagdhghyihjzjkknlylomymtntoxpyprrhrtsttotluovlwdwnyazmambtbbcwcpdtdyemfmfegsguhthsisjlkokilrlukbsnmolt" }
};

#define BYTEWORDS_VECTOR_COUNT (sizeof(BYTEWORDS_VECTORS) / sizeof(BYTEWORDS_VECTORS[0]))

/* Every row here has to answer 0, no decoded length. The encodings are hex because several carry
 * bytes that are not letters: a decoder that indexes a table with letters scanned off a QR has to
 * answer those without reading outside the table. */
typedef struct {
  const char* name;
  const char* encoded;
} bytewords_invalid_t;

static const bytewords_invalid_t BYTEWORDS_INVALID[] = {
  { "empty", "" },
  { "three words, no room for a checksum", "61656164616f" },
  { "odd number of letters", "61656164616f6c" },
  { "checksum of the empty payload", "6165616561656165" },
  { "payload reversed, checksum left where it was", "7a6d6c61616f616461656a656e64656f7469" },
  { "first payload letter changed", "7a656164616f6c617a6d6a656e64656f7469" },
  { "last checksum letter changed", "61656164616f6c617a6d6a656e64656f747a" },
  { "standard style: spaces between the words", "616520616420616f206c61207a6d206a65206e6420656f207469" },
  { "uri style: hyphens between the words", "61652d61642d616f2d6c612d7a6d2d6a652d6e642d656f2d7469" },
  { "space between two words", "6165206164616f6c617a6d6a656e64656f7469" },
  { "digit among the letters", "31656164616f6c617a6d6a656e64656f7469" },
  { "nul byte among the letters", "006164616f6c617a6d6a656e64656f7469" },
  { "byte above ascii among the letters", "806164616f6c617a6d6a656e64656f7469" },
  { "0xff among the letters", "ff6164616f6c617a6d6a656e64656f7469" },
  { "high byte in every position", "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3" },
  { "letters that are not a word, in every position", "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" },
  { "bc-bytewords literal with a corrupted checksum", "61656164616f6c617a6f6a656e64656f7766" }
};

#define BYTEWORDS_INVALID_COUNT (sizeof(BYTEWORDS_INVALID) / sizeof(BYTEWORDS_INVALID[0]))

#endif
