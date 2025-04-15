#ifndef __COMMAND_H
#define __COMMAND_H

#include <stdint.h>
#include "iso7816/smartcard.h"
#include "error.h"

#define INS_GET_ETH_ADDR 0x02
#define INS_SIGN_ETH_TX 0x04
#define INS_GET_APP_CONF 0x06
#define INS_SIGN_ETH_MSG 0x08
#define INS_SIGN_EIP_712 0x0c
#define INS_SIGN_PSBT 0x0e
#define INS_GET_RESPONSE 0xc0
#define INS_FW_UPGRADE 0xf2
#define INS_ERC20_UPGRADE 0xf4

#define USB_CMD_MAX_PAYLOAD 253

typedef enum {
  COMMAND_INBOUND = 0,
  COMMAND_COMPLETE,
  COMMAND_PROCESSING,
  COMMAND_OUTBOUND
} command_status_t;

typedef struct {
  command_status_t status;
  uint16_t to_rxtx;
  uint16_t segment_count;
  uint16_t extra_len;
  uint8_t* extra_data;
  apdu_t apdu;
} command_t;

app_err_t command_init_recv(command_t* cmd, uint16_t len);
void command_init_send(command_t* cmd);
void command_receive(command_t* cmd, uint8_t* data, uint8_t len);
uint8_t command_send(command_t* cmd, uint8_t* buf, uint8_t len);
void command_send_ack(command_t* cmd, uint8_t len);

#endif
