#include "stm32_internal.h"
#include "crypto/memzero.h"

const uint8_t BN_ONE[BN_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

hal_err_t hal_rng_next(uint8_t *buf, size_t len) {
  uint32_t rnd;

  while(len >= 4) {
    while (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK) {}
    len -= 4;
    memcpy(buf, &rnd, 4);
    buf += 4;
  }

  if (len) {
    while (HAL_RNG_GenerateRandomNumber(&hrng, &rnd) != HAL_OK) {}
    memcpy(buf, &rnd, len);
  }

  memzero(&rnd, sizeof(rnd));
  return HAL_SUCCESS;
}

hal_err_t hal_crc32_init(hal_crc32_ctx_t* ctx) {
  __HAL_CRC_DR_RESET(&hcrc);
  return HAL_SUCCESS;
}

hal_err_t hal_crc32_update(hal_crc32_ctx_t* ctx, uint8_t b) {
  *(__IO uint8_t *)(__IO void *)(&hcrc.Instance->DR) = b;
  return HAL_SUCCESS;
}

hal_err_t hal_crc32_finish(hal_crc32_ctx_t* ctx, uint32_t *out) {
  *out = ~hcrc.Instance->DR;
  return HAL_SUCCESS;
}

hal_err_t hal_sha256_init(hal_sha256_ctx_t* ctx) {
  ctx->len = 0;
  ctx->buf = 0;
  CLEAR_BIT(hhash.Instance->CR, HASH_CR_MODE);
  MODIFY_REG(hhash.Instance->CR, HASH_CR_INIT, HASH_CR_INIT);

  return HAL_SUCCESS;
}

hal_err_t hal_sha256_update(hal_sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
  uint8_t rest = ctx->len & 3;
  ctx->len += len;

  if (rest) {
    switch(rest) {
    case 1:
      ctx->buf = (ctx->buf & 0x000000ff) | (data[2] << 24) | (data[1] << 16) | (data[0] << 8);
      data += 3;
      len -= 3;
      break;
    case 2:
      ctx->buf = (ctx->buf & 0x0000ffff) | (data[1] << 24) | (data[0] << 16);
      data += 2;
      len -= 2;
      break;
    case 3:
    default:
      ctx->buf = (ctx->buf & 0x00ffffff) | (data[0] << 24);
      data++;
      len--;
      break;
    }

    if (((int32_t) len) >= 0) {
      hhash.Instance->DIN = ctx->buf;
      ctx->buf = 0;
    } else {
      return HAL_SUCCESS;
    }
  }

  __IO uint32_t data32 = (uint32_t) data;

  for (int i = 0; i < (len & ~3) ; i += 4) {
    hhash.Instance->DIN = *(uint32_t *)data32;
    data32 += 4;
  }

  rest = len & 3;
  if (rest) {
    switch(rest) {
    case 1:
      ctx->buf = data[len - 1];
      break;
    case 2:
      ctx->buf = data[len - 2] | (data[len - 1] << 8);
      break;
    case 3:
    default:
      ctx->buf = data[len - 3] | (data[len - 2] << 8) | (data[len - 1] << 16);
      break;
    }
  }

  return HAL_SUCCESS;
}

hal_err_t hal_sha256_finish(hal_sha256_ctx_t* ctx, uint8_t out[SHA256_DIGEST_LENGTH]) {
  uint8_t rest = ctx->len & 3;

  if (rest) {
    hhash.Instance->DIN = ctx->buf;
  }

  HAL_WAIT(__HAL_HASH_GET_FLAG(&hhash, HASH_FLAG_BUSY) == SET);

  MODIFY_REG(hhash.Instance->STR, HASH_STR_NBLW, 8 * rest);
  SET_BIT(hhash.Instance->STR, HASH_STR_DCAL);

  HAL_WAIT(__HAL_HASH_GET_FLAG(&hhash, HASH_FLAG_DCIS) == RESET);

  __IO uint32_t* out32 = (uint32_t *) out;

  *(out32++) = __REV(hhash.Instance->HR[0]);
  *(out32++) = __REV(hhash.Instance->HR[1]);
  *(out32++) = __REV(hhash.Instance->HR[2]);
  *(out32++) = __REV(hhash.Instance->HR[3]);
  *(out32++) = __REV(hhash.Instance->HR[4]);
  *(out32++) = __REV(HASH_DIGEST->HR[5]);
  *(out32++) = __REV(HASH_DIGEST->HR[6]);
  *(out32++) = __REV(HASH_DIGEST->HR[7]);

  return HAL_SUCCESS;
}

static inline void _hal_aes256_load_iv(const uint8_t iv[AES_IV_SIZE]) {
  SAES->IVR3 = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
  SAES->IVR2 = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];
  SAES->IVR1 = (iv[8] << 24) | (iv[9] << 16) | (iv[10] << 8) | iv[11];
  SAES->IVR0 = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];
}

static inline void _hal_aes256_load_key(const uint8_t key[AES_256_KEY_SIZE]) {
  SAES->KEYR7 = (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
  SAES->KEYR6 = (key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7];
  SAES->KEYR5 = (key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11];
  SAES->KEYR4 = (key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15];
  SAES->KEYR3 = (key[16] << 24) | (key[17] << 16) | (key[18] << 8) | key[19];
  SAES->KEYR2 = (key[20] << 24) | (key[21] << 16) | (key[22] << 8) | key[23];
  SAES->KEYR1 = (key[24] << 24) | (key[25] << 16) | (key[26] << 8) | key[27];
  SAES->KEYR0 = (key[28] << 24) | (key[29] << 16) | (key[30] << 8) | key[31];
}

hal_err_t hal_aes256_init(hal_aes_mode_t mode, hal_aes_chaining_t chaining, const uint8_t key[AES_256_KEY_SIZE], const uint8_t iv[AES_IV_SIZE]) {
  assert(chaining == AES_CBC);

  HAL_WAIT((SAES->SR & AES_SR_BUSY));

  uint32_t cr = AES_CR_CHMOD_0 | AES_CR_KEYSIZE | AES_CR_DATATYPE_1;

  if (mode == AES_ENCRYPT) {
    SAES->CR = cr;
  } else {
    SAES->CR = cr | AES_CR_MODE_0;
  }

  _hal_aes256_load_key(key);

  HAL_WAIT(!(SAES->SR & AES_SR_KEYVALID));

  if (mode == AES_DECRYPT) {
    SAES->CR = cr | AES_CR_MODE_0 | AES_CR_EN;

    HAL_WAIT(!(SAES->SR & AES_SR_CCF));

    SAES->ICR = AES_ICR_CCF;

    cr |= AES_CR_MODE_1;
    SAES->CR = cr;
  }

  _hal_aes256_load_iv(iv);
  SAES->CR = cr | AES_CR_EN;

  return HAL_SUCCESS;
}

hal_err_t hal_aes256_block_process(const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) {
  __IO uint32_t* in32 = (uint32_t*) in;
  __IO uint32_t* out32 = (uint32_t*) out;

  SAES->DINR = in32[0];
  SAES->DINR = in32[1];
  SAES->DINR = in32[2];
  SAES->DINR = in32[3];

  HAL_WAIT(!(SAES->SR & AES_SR_CCF));

  SAES->ICR = AES_ICR_CCF;

  out32[0] = SAES->DOUTR;
  out32[1] = SAES->DOUTR;
  out32[2] = SAES->DOUTR;
  out32[3] = SAES->DOUTR;

  return HAL_SUCCESS;
}

hal_err_t hal_aes256_finalize() {
  SAES->CR = AES_CR_IPRST;
  HAL_WAIT((SAES->SR & AES_SR_BUSY));
  SAES->CR = 0;

  return HAL_SUCCESS;
}

static hal_err_t _hal_saes_wrap_key(const uint8_t key[32], uint8_t out[32]) {
  HAL_WAIT((SAES->SR & AES_SR_BUSY));

  uint32_t cr = AES_CR_KMOD_0 | AES_CR_KEYSIZE | AES_CR_KEYSEL_0;
  SAES->CR = cr;
  HAL_WAIT(!(SAES->SR & AES_SR_KEYVALID));
  SAES->CR = cr | AES_CR_EN;

  if (hal_aes256_block_process(key, out) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  if (hal_aes256_block_process(&key[16], &out[16]) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  return hal_aes256_finalize();
}

hal_err_t hal_derive_device_unique_secret(const uint8_t salt[32], uint8_t out[32]) {
  if (_hal_saes_wrap_key(salt, out) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  hal_sha256_ctx_t sha;
  hal_sha256_init(&sha);
  hal_sha256_update(&sha, out, 32);
  return hal_sha256_finish(&sha, out);
}

static hal_err_t _hal_bn_r2(const uint8_t mod[BN_SIZE], uint32_t* r2_mod) {
  PKA_MontgomeryParamInTypeDef mont;
  mont.pOp1 = mod;
  mont.size = BN_SIZE;
  if (HAL_PKA_MontgomeryParam(&hpka, &mont, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  HAL_PKA_MontgomeryParam_GetResult(&hpka, r2_mod);

  return HAL_OK;
}


hal_err_t hal_ecdsa_sign(const ecdsa_curve* curve, const uint8_t* priv_key, const uint8_t* digest, const uint8_t* k, uint8_t* sig_out) {
  PKA_ECDSASignInTypeDef sign_params;
  sign_params.modulus = curve->prime;
  sign_params.modulusSize = ECC256_ELEMENT_SIZE;
  sign_params.basePointX = curve->G;
  sign_params.basePointY = &curve->G[ECC256_ELEMENT_SIZE];
  sign_params.coef = curve->a;
  sign_params.coefSign = curve->a_sign & 1;
  sign_params.coefB = curve->b;
  sign_params.primeOrder = curve->order;
  sign_params.primeOrderSize = ECC256_ELEMENT_SIZE;
  sign_params.hash = digest;
  sign_params.integer = k;
  sign_params.privateKey = priv_key;

  if (HAL_PKA_ECDSASign(&hpka, &sign_params, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  PKA_ECDSASignOutTypeDef out;
  out.RSign = sig_out;
  out.SSign = &sig_out[ECC256_ELEMENT_SIZE];

  HAL_PKA_ECDSASign_GetResult(&hpka, &out, NULL);

  return HAL_SUCCESS;
}

hal_err_t hal_ecdsa_verify(const ecdsa_curve* curve, const uint8_t* pub_key, const uint8_t* sig, const uint8_t* digest) {
  PKA_ECDSAVerifInTypeDef verify_params;

  verify_params.modulus = curve->prime;
  verify_params.modulusSize = ECC256_ELEMENT_SIZE;
  verify_params.basePointX = curve->G;
  verify_params.basePointY = &curve->G[ECC256_ELEMENT_SIZE];
  verify_params.coef = curve->a;
  verify_params.coefSign = curve->a_sign & 1;
  verify_params.primeOrder = curve->order;
  verify_params.primeOrderSize = ECC256_ELEMENT_SIZE;
  verify_params.hash = digest;
  verify_params.pPubKeyCurvePtX = pub_key;
  verify_params.pPubKeyCurvePtY = &pub_key[ECC256_ELEMENT_SIZE];
  verify_params.RSign = sig;
  verify_params.SSign = &sig[ECC256_ELEMENT_SIZE];

  if (HAL_PKA_ECDSAVerif(&hpka, &verify_params, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  return HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) ? HAL_SUCCESS : HAL_FAIL;
}

hal_err_t hal_ec_point_multiply(const ecdsa_curve* curve, const uint8_t* scalar, const uint8_t* point, uint8_t* point_out) {
  PKA_ECCMulInTypeDef mult;

  mult.modulus = curve->prime;
  mult.modulusSize = ECC256_ELEMENT_SIZE;
  mult.coefA = curve->a;
  mult.coefSign = curve->a_sign & 1;
  mult.coefB = curve->b;
  mult.primeOrder = curve->order;
  mult.pointX = point;
  mult.pointY = &point[ECC256_ELEMENT_SIZE];
  mult.scalarMul = scalar;
  mult.scalarMulSize = ECC256_ELEMENT_SIZE;

  if (HAL_PKA_ECCMul(&hpka, &mult, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  PKA_ECCMulOutTypeDef out;
  out.ptX = point_out;
  out.ptY = &point_out[ECC256_ELEMENT_SIZE];

  HAL_PKA_ECCMul_GetResult(&hpka, &out);

  return HAL_SUCCESS;
}

hal_err_t hal_ec_double_ladder(const ecdsa_curve* curve, const uint8_t* s1, const uint8_t* p1, const uint8_t* s2, const uint8_t* p2, uint8_t* point_out) {
  PKA_ECCDoubleBaseLadderInTypeDef dbl;
  dbl.modulus = curve->prime;
  dbl.modulusSize = ECC256_ELEMENT_SIZE;
  dbl.primeOrderSize = ECC256_ELEMENT_SIZE;
  dbl.coefA = curve->a;
  dbl.coefSign = curve->a_sign & 1;
  dbl.integerK = s1;
  dbl.basePointX1 = p1;
  dbl.basePointY1 = &p1[ECC256_ELEMENT_SIZE];
  dbl.basePointZ1 = BN_ONE;
  dbl.integerM = s2;
  dbl.basePointX2 = p2;
  dbl.basePointY2 = &p2[ECC256_ELEMENT_SIZE];
  dbl.basePointZ2 = BN_ONE;

  if (HAL_PKA_ECCDoubleBaseLadder(&hpka, &dbl, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  PKA_ECCDoubleBaseLadderOutTypeDef out;
  out.ptX = point_out;
  out.ptY = &point_out[ECC256_ELEMENT_SIZE];

  HAL_PKA_ECCDoubleBaseLadder_GetResult(&hpka, &out);

  return HAL_SUCCESS;
}

hal_err_t hal_ec_point_check(const ecdsa_curve* curve, const uint8_t* point) {
  uint32_t r2_mod[BN_SIZE/4];
  if (_hal_bn_r2(curve->prime, r2_mod) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  PKA_PointCheckInTypeDef pc;
  pc.modulus = curve->prime;
  pc.modulusSize = ECC256_ELEMENT_SIZE;
  pc.coefA = curve->a;
  pc.coefSign = curve->a_sign & 1;
  pc.coefB = curve->b;
  pc.pointX = point;
  pc.pointY = &point[ECC256_ELEMENT_SIZE];
  pc.pMontgomeryParam = r2_mod;

  if (HAL_PKA_PointCheck(&hpka, &pc, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  return HAL_PKA_PointCheck_IsOnCurve(&hpka) ? HAL_SUCCESS : HAL_FAIL;
}

static void _hal_pka_ari_set(const uint8_t *pOp1, const uint8_t *pOp2, const uint8_t *pOp3) {
  hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_NB_BITS] = BN_SIZE * 8;

  if (pOp1 != NULL) {
    PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_IN_OP1], pOp1, BN_SIZE);
    __PKA_RAM_PARAM_END(hpka.Instance->RAM, (PKA_ARITHMETIC_ALL_OPS_IN_OP1 + (BN_SIZE / 4)));
  }

  if (pOp2 != NULL) {
    PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_IN_OP2], pOp2, BN_SIZE);
    __PKA_RAM_PARAM_END(hpka.Instance->RAM, (PKA_ARITHMETIC_ALL_OPS_IN_OP2 + (BN_SIZE / 4)));
  }

  if (pOp3 != NULL) {
    PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_IN_OP3], pOp3, BN_SIZE);
    __PKA_RAM_PARAM_END(hpka.Instance->RAM, (PKA_ARITHMETIC_ALL_OPS_IN_OP3 + (BN_SIZE / 4)));
  }
}

static inline hal_err_t _hal_pka_ari_do(uint32_t op, const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  _hal_pka_ari_set(a, b, mod);
  if (PKA_Process(&hpka, op, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  PKA_Memcpy_u32_to_u8(r, &hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_OUT_RESULT], BN_SIZE);

  return HAL_OK;
}

hal_err_t hal_bn_mul_r2(const uint8_t a[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  uint32_t r2_mod[BN_SIZE/4];
  if (_hal_bn_r2(mod, r2_mod) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_NB_BITS] = BN_SIZE * 8;
  PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_IN_OP1], a, BN_SIZE);
  __PKA_RAM_PARAM_END(hpka.Instance->RAM, (PKA_ARITHMETIC_ALL_OPS_IN_OP1 + (BN_SIZE / 4)));

  PKA_Memcpy_u32_to_u32(&hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_IN_OP2], r2_mod, (BN_SIZE / 4));
  __PKA_RAM_PARAM_END(hpka.Instance->RAM, (PKA_ARITHMETIC_ALL_OPS_IN_OP2 + (BN_SIZE / 4)));

  PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_IN_OP3], mod, BN_SIZE);
  __PKA_RAM_PARAM_END(hpka.Instance->RAM, (PKA_ARITHMETIC_ALL_OPS_IN_OP3 + (BN_SIZE / 4)));

  if (PKA_Process(&hpka, PKA_MODE_MONTGOMERY_MUL, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  PKA_Memcpy_u32_to_u8(r, &hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_OUT_RESULT], BN_SIZE);

  return HAL_SUCCESS;
}

hal_err_t hal_bn_mul_mont(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  return _hal_pka_ari_do(PKA_MODE_MONTGOMERY_MUL, a, b, mod, r);
}

hal_err_t hal_bn_mul_mod(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  uint8_t tmp[BN_SIZE];
  if (hal_bn_mul_r2(a, mod, tmp) != HAL_SUCCESS) {
    return HAL_FAIL;
  }

  return hal_bn_mul_mont(tmp, b, mod, r);
}

hal_err_t hal_bn_add(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]) {
  return _hal_pka_ari_do(PKA_MODE_ARITHMETIC_ADD, a, b, NULL, r);
}

hal_err_t hal_bn_sub(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]) {
  return _hal_pka_ari_do(PKA_MODE_ARITHMETIC_SUB, a, b, NULL, r);
}

hal_err_t hal_bn_mul(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], uint8_t r[BN_SIZE]) {
  return _hal_pka_ari_do(PKA_MODE_ARITHMETIC_MUL, a, b, NULL, r);
}

hal_err_t hal_bn_add_mod(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  return _hal_pka_ari_do(PKA_MODE_MODULAR_ADD, a, b, mod, r);
}

hal_err_t hal_bn_sub_mod(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  return _hal_pka_ari_do(PKA_MODE_MODULAR_SUB, a, b, mod, r);
}

hal_err_t hal_bn_exp_mod(const uint8_t a[BN_SIZE], const uint8_t e[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  PKA_ModExpInTypeDef exp;

  exp.OpSize = BN_SIZE;
  exp.expSize = BN_SIZE;
  exp.pOp1 = a;
  exp.pExp = e;
  exp.pMod = mod;

  if (HAL_PKA_ModExp(&hpka, &exp, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  HAL_PKA_ModExp_GetResult(&hpka, r);

  return HAL_SUCCESS;
}

hal_err_t hal_bn_inv_mod(const uint8_t a[BN_SIZE], const uint8_t mod[BN_SIZE], uint8_t r[BN_SIZE]) {
  PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_MODULAR_INV_IN_OP1], a, BN_SIZE);
  __PKA_RAM_PARAM_END(hpka.Instance->RAM, PKA_MODULAR_INV_IN_OP1 + (BN_SIZE / 4));

  PKA_Memcpy_u8_to_u32(&hpka.Instance->RAM[PKA_MODULAR_INV_IN_OP2_MOD], mod, BN_SIZE);
  __PKA_RAM_PARAM_END(hpka.Instance->RAM, PKA_MODULAR_INV_IN_OP2_MOD + (BN_SIZE / 4));

  if (PKA_Process(&hpka, PKA_MODE_MODULAR_INV, PKA_TIMEOUT) != HAL_OK) {
    return HAL_FAIL;
  }

  PKA_Memcpy_u32_to_u8(r, &hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_OUT_RESULT], BN_SIZE);

  return HAL_OK;
}

int hal_bn_cmp(const uint8_t a[BN_SIZE], const uint8_t b[BN_SIZE]) {
  _hal_pka_ari_set(a, b, NULL);
  if (PKA_Process(&hpka, PKA_MODE_COMPARISON, PKA_TIMEOUT) != HAL_OK) {
    return INT32_MAX;
  }

  uint32_t res = hpka.Instance->RAM[PKA_ARITHMETIC_ALL_OPS_OUT_RESULT];

  switch(res) {
  case 0x916a:
    return -1;
  case 0xed2c:
    return 0;
  case 0x7af8:
    return 1;
  default:
    return INT32_MAX;
  }
}
