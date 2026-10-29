#ifndef _VARIANT_H_
#define _VARIANT_H_

/* Build variants, carried in the three most significant bits of the beta byte of FW_VERSION.
 * That byte is masked out of the firmware downgrade comparison and is covered by the firmware
 * signature (which digests everything but the signature itself), so the variant travels with the
 * image, survives a bank swap, and cannot be altered without invalidating the signature.
 * GET DEVICE INFO reports the two fields as separate bytes. */
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

#define FW_VARIANT_MASK 0xe0
#define FW_VARIANT_SHIFT 5
#define FW_BETA_MASK 0x1f

#define FW_VERSION_BYTE(__BETA__, __VARIANT__) \
  (((__VARIANT__) << FW_VARIANT_SHIFT) | ((__BETA__) & FW_BETA_MASK))

#define FW_BETA_OF(__VERSION_BYTE__) ((__VERSION_BYTE__) & FW_BETA_MASK)
#define FW_VARIANT_OF(__VERSION_BYTE__) \
  (((__VERSION_BYTE__) >> FW_VARIANT_SHIFT) & (FW_VARIANT_MASK >> FW_VARIANT_SHIFT))

#endif
