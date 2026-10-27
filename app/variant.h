#ifndef _VARIANT_H_
#define _VARIANT_H_

/* Build variants, carried in the two most significant bits of the beta byte of FW_VERSION.
 * That byte is masked out of the firmware downgrade comparison and is covered by the firmware
 * signature (which digests everything but the signature itself), so the variant travels with the
 * image, survives a bank swap, and cannot be altered without invalidating the signature. */
#define FW_VARIANT_OMNI 0
#define FW_VARIANT_BTC 1

#ifdef BITCOIN_ONLY
#define FW_VARIANT FW_VARIANT_BTC
#else
#define FW_VARIANT FW_VARIANT_OMNI
#endif

#if (FW_VARIANT != FW_VARIANT_OMNI) && (FW_VARIANT != FW_VARIANT_BTC)
#error "FW_VARIANT must be FW_VARIANT_OMNI or FW_VARIANT_BTC"
#endif

#define FW_VARIANT_MASK 0xc0
#define FW_VARIANT_SHIFT 6

#define FW_VERSION_BYTE(__BETA__, __VARIANT__) \
  (((__VARIANT__) << FW_VARIANT_SHIFT) | ((__BETA__) & ~FW_VARIANT_MASK))

#define FW_BETA_OF(__VERSION_BYTE__) ((__VERSION_BYTE__) & ~FW_VARIANT_MASK)
#define FW_VARIANT_OF(__VERSION_BYTE__) (((__VERSION_BYTE__) >> FW_VARIANT_SHIFT) & 0x03)

#endif
