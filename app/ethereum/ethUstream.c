/*******************************************************************************
 *   Ledger Ethereum App
 *   (c) 2016-2019 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <stdint.h>
#include <string.h>

#include "ethUstream.h"
#include "ethUtils.h"
#include "common.h"

#define MAX_INT256  32
#define MAX_ADDRESS 20

#define EXCEPTION 0x100

void initTx(txContext_t *context, SHA3_CTX *sha3, txContent_t *content) {
  memset(context, 0, sizeof(txContext_t));
  memset(content->destination, 0, ADDRESS_LENGTH);
  context->sha3 = sha3;
  context->content = content;
  context->currentField = RLP_NONE + 1;
}

uint16_t readTxByte(txContext_t *context) {
  uint8_t data;
  if (context->commandLength < 1) {
    return EXCEPTION;
  }
  data = *context->workBuffer;
  context->workBuffer++;
  context->commandLength--;
  if (context->processingField) {
    context->currentFieldPos++;
  }
  if (!(context->processingField && context->fieldSingleByte)) {
    keccak_Update(context->sha3, &data, 1);
  }
  return data;
}

uint16_t copyTxData(txContext_t *context, uint8_t *out, uint32_t length) {
  if (context->commandLength < length) {
    return EXCEPTION;
  }

  if (out != NULL) {
    memmove(out, context->workBuffer, length);
  }

  if (!(context->processingField && context->fieldSingleByte)) {
    keccak_Update(context->sha3, context->workBuffer, length);
  }
  context->workBuffer += length;
  context->commandLength -= length;
  if (context->processingField) {
    context->currentFieldPos += length;
  }

  return 0;
}

static uint16_t processContent(txContext_t *context) {
  if (!context->currentFieldIsList) {
    return EXCEPTION;
  }

  context->currentField++;
  context->processingField = false;
  return 0;
}

static uint16_t processAccessList(txContext_t *context) {
  if (!context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, NULL, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }

  if (context->currentFieldPos == context->currentFieldLength) {
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

inline static uint16_t processAuthList(txContext_t* context) {
  return processAccessList(context);
}

static uint16_t processChainID(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldLength > sizeof(context->content->chainID)) {
    return EXCEPTION;
  }

  const uint8_t* chainBuf = context->workBuffer;

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, NULL, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }
  if (context->currentFieldPos == context->currentFieldLength) {
    context->content->chainID = u32_from_BE(chainBuf, context->currentFieldLength);
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processNonce(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }
  if (context->currentFieldLength > MAX_INT256) {
    return EXCEPTION;
  }
  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, NULL, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }
  if (context->currentFieldPos == context->currentFieldLength) {
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processStartGas(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldLength > MAX_INT256) {
    return EXCEPTION;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, context->content->startgas.value + context->currentFieldPos, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }
  if (context->currentFieldPos == context->currentFieldLength) {
    context->content->startgas.length = context->currentFieldLength;
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

inline static uint16_t processGasLimit(txContext_t *context) {
  return processStartGas(context);
}

static uint16_t processGasprice(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldLength > MAX_INT256) {
    return EXCEPTION;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, context->content->gasprice.value + context->currentFieldPos, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }

  if (context->currentFieldPos == context->currentFieldLength) {
    context->content->gasprice.length = context->currentFieldLength;
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processValue(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldLength > MAX_INT256) {
    return EXCEPTION;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, context->content->value.value + context->currentFieldPos, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }

  if (context->currentFieldPos == context->currentFieldLength) {
    context->content->value.length = context->currentFieldLength;
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processTo(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldLength > MAX_ADDRESS) {
    return EXCEPTION;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    int padding = MAX_ADDRESS - context->currentFieldLength;
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, context->content->destination + padding + context->currentFieldPos, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }

  if (context->currentFieldPos == context->currentFieldLength) {
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processData(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldPos == 0) {
    if (context->content->data == NULL) {
      context->content->data = context->workBuffer;
    }

    context->content->dataLength = 0;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    uint8_t* copyBuffer = (uint8_t*) (context->content->data + context->content->dataLength);

    if (context->workBuffer == copyBuffer) {
      copyBuffer = NULL;
    }

    if (copyTxData(context, copyBuffer, copySize) == EXCEPTION) {
      return EXCEPTION;
    }

    context->content->dataLength += copySize;
  }

  if (context->currentFieldPos == context->currentFieldLength) {
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processAndDiscard(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, NULL, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }
  if (context->currentFieldPos == context->currentFieldLength) {
    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static uint16_t processV(txContext_t *context) {
  if (context->currentFieldIsList) {
    return EXCEPTION;
  }

  if (context->currentFieldLength > sizeof(context->content->v)) {
    return EXCEPTION;
  }

  const uint8_t* vBuf = context->workBuffer;

  if (context->currentFieldPos < context->currentFieldLength) {
    uint32_t copySize = APP_MIN(context->commandLength, context->currentFieldLength - context->currentFieldPos);
    if (copyTxData(context, NULL, copySize) == EXCEPTION) {
      return EXCEPTION;
    }
  }

  if (context->currentFieldPos == context->currentFieldLength) {
    if (context->currentFieldLength == 0) {
      context->content->v = V_NONE;
    } else {
      context->content->v = u32_from_BE(vBuf, context->currentFieldLength);
      context->content->chainID = context->content->v;
    }

    context->currentField++;
    context->processingField = false;
  }

  return 0;
}

static bool processEIP7702Tx(txContext_t *context) {
  switch (context->currentField) {
    case EIP7702_RLP_CONTENT: {
      if (processContent(context) == EXCEPTION) {
        return true;
      }
      context->currentField++;
      return false;
    }
    case EIP7702_RLP_CHAINID:
      return processChainID(context) == EXCEPTION;
    case EIP7702_RLP_NONCE:
      return processNonce(context) == EXCEPTION;
    case EIP7702_RLP_MAX_FEE_PER_GAS:
      return processGasprice(context) == EXCEPTION;
    case EIP7702_RLP_GASLIMIT:
      return processGasLimit(context) == EXCEPTION;
    case EIP7702_RLP_TO:
      return processTo(context) == EXCEPTION;
    case EIP7702_RLP_VALUE:
      return processValue(context) == EXCEPTION;
    case EIP7702_RLP_DATA:
      return processData(context) == EXCEPTION;
    case EIP7702_RLP_ACCESS_LIST:
      return processAccessList(context) == EXCEPTION;
    case EIP7702_RLP_AUTH_LIST:
      return processAuthList(context) == EXCEPTION;
    case EIP7702_RLP_MAX_PRIORITY_FEE_PER_GAS:
      return processAndDiscard(context) == EXCEPTION;
    default:
      return true;
  }
}

static bool processEIP1559Tx(txContext_t *context) {
  switch (context->currentField) {
    case EIP1559_RLP_CONTENT: {
      if (processContent(context) == EXCEPTION) {
        return true;
      }
      context->currentField++;
      return false;
    }
    case EIP1559_RLP_CHAINID:
      return processChainID(context) == EXCEPTION;
    case EIP1559_RLP_NONCE:
      return processNonce(context) == EXCEPTION;
    case EIP1559_RLP_MAX_FEE_PER_GAS:
      return processGasprice(context) == EXCEPTION;
    case EIP1559_RLP_GASLIMIT:
      return processStartGas(context) == EXCEPTION;
    case EIP1559_RLP_TO:
      return processTo(context) == EXCEPTION;
    case EIP1559_RLP_VALUE:
      return processValue(context) == EXCEPTION;
    case EIP1559_RLP_DATA:
      return processData(context) == EXCEPTION;
    case EIP1559_RLP_ACCESS_LIST:
      return processAccessList(context) == EXCEPTION;
    case EIP1559_RLP_MAX_PRIORITY_FEE_PER_GAS:
      return processAndDiscard(context) == EXCEPTION;
    default:
      return true;
  }
}

static bool processEIP2930Tx(txContext_t *context) {
  switch (context->currentField) {
    case EIP2930_RLP_CONTENT:
      if (processContent(context) == EXCEPTION) {
        return true;
      }
      context->currentField++;
      return false;
    case EIP2930_RLP_CHAINID:
      return processChainID(context) == EXCEPTION;
    case EIP2930_RLP_NONCE:
      return processNonce(context) == EXCEPTION;
    case EIP2930_RLP_GASPRICE:
      return processGasprice(context) == EXCEPTION;
    case EIP2930_RLP_GASLIMIT:
      return processStartGas(context) == EXCEPTION;
    case EIP2930_RLP_TO:
      return processTo(context) == EXCEPTION;
    case EIP2930_RLP_VALUE:
      return processValue(context) == EXCEPTION;
    case EIP2930_RLP_DATA:
      return processData(context) == EXCEPTION;
    case EIP2930_RLP_ACCESS_LIST:
      return processAccessList(context) == EXCEPTION;
    default:
      return true;
  }
}

static bool processLegacyTx(txContext_t *context) {
  switch (context->currentField) {
    case LEGACY_RLP_CONTENT:
      if (processContent(context) == EXCEPTION) {
        return true;
      }
      context->currentField++;
      return false;
    case LEGACY_RLP_NONCE:
      return processNonce(context) == EXCEPTION;
      break;
    case LEGACY_RLP_GASPRICE:
      return processGasprice(context) == EXCEPTION;
    case LEGACY_RLP_STARTGAS:
      return processStartGas(context) == EXCEPTION;
      break;
    case LEGACY_RLP_TO:
      return processTo(context) == EXCEPTION;
      break;
    case LEGACY_RLP_VALUE:
      return processValue(context) == EXCEPTION;
      break;
    case LEGACY_RLP_DATA:
      return processData(context) == EXCEPTION;
      break;
    case LEGACY_RLP_R:
    case LEGACY_RLP_S:
      return processAndDiscard(context) == EXCEPTION;
      break;
    case LEGACY_RLP_V:
      return processV(context) == EXCEPTION;
      break;
    default:
      return true;
  }
}

static parserStatus_e parseRLP(txContext_t *context) {
  bool canDecode = false;
  uint32_t offset;
  while (context->commandLength != 0) {
    bool valid;
    // Feed the RLP buffer until the length can be decoded
    uint16_t dataByte = readTxByte(context);
    if (dataByte == EXCEPTION) {
      return USTREAM_FAULT;
    }

    context->rlpBuffer[context->rlpBufferPos++] = dataByte;
    if (rlpCanDecode(context->rlpBuffer, context->rlpBufferPos, &valid)) {
      // Can decode now, if valid
      if (!valid) {
        return USTREAM_FAULT;
      }

      canDecode = true;
      break;
    }
    // Cannot decode yet
    // Sanity check
    if (context->rlpBufferPos == sizeof(context->rlpBuffer)) {
      return USTREAM_FAULT;
    }
  }

  if (!canDecode) {
    return USTREAM_PROCESSING;
  }

  // Ready to process this field
  if (!rlpDecodeLength(context->rlpBuffer, &context->currentFieldLength, &offset, &context->currentFieldIsList)) {
    return USTREAM_FAULT;
  }

  // Ready to process this field
  if (offset == 0) {
    // Hack for single byte, self encoded
    context->workBuffer--;
    context->commandLength++;
    context->fieldSingleByte = true;
  } else {
    context->fieldSingleByte = false;
  }
  context->currentFieldPos = 0;
  context->rlpBufferPos = 0;
  context->processingField = true;
  return USTREAM_CONTINUE;
}

parserStatus_e continueTx(txContext_t *context) {
  for (;;) {
    // EIP 155 style transaction
    if (PARSING_IS_DONE(context)) {
      return USTREAM_FINISHED;
    }
    // Old style transaction (pre EIP-155). Transations could just skip `v,r,s` so we needed to
    // cut parsing here. commandLength == 0 could happen in two cases :
    // 1. We are in an old style transaction : just return `USTREAM_FINISHED`.
    // 2. We are at the end of an APDU in a multi-apdu process. This would make us return
    // `USTREAM_FINISHED` preemptively. Case number 2 should NOT happen as it is up to
    // `ledgerjs` to correctly decrease the size of the APDU (`commandLength`) so that this
    // situation doesn't happen.
    if ((context->txType == LEGACY && context->currentField == LEGACY_RLP_V) && (context->commandLength == 0)) {
      context->content->v = V_NONE;
      return USTREAM_FINISHED;
    }

    if (context->commandLength == 0) {
      return USTREAM_PROCESSING;
    }

    if (!context->processingField) {
      parserStatus_e status = parseRLP(context);
      if (status != USTREAM_CONTINUE) {
        return status;
      }
    }

    switch (context->txType) {
      case LEGACY:
        if (processLegacyTx(context)) {
          return USTREAM_FAULT;
        } else {
          break;
        }
      case EIP2930:
        if (processEIP2930Tx(context)) {
          return USTREAM_FAULT;
        } else {
          break;
        }
      case EIP1559:
        if (processEIP1559Tx(context)) {
          return USTREAM_FAULT;
        } else {
          break;
        }
      case EIP7702:
        if (processEIP7702Tx(context)) {
          return USTREAM_FAULT;
        } else {
          break;
        }
      default:
        return USTREAM_FAULT;
    }
  }
}

parserStatus_e processTx(txContext_t *context, const uint8_t *buffer, uint32_t length) {
  context->workBuffer = buffer;
  context->commandLength = length;
  return continueTx(context);
}
