#ifndef __KEYCARD_H
#define __KEYCARD_H

#include "secure_channel.h"
#include "command.h"
#include "iso7816/smartcard.h"

#define KEYCARD_PIN_LEN 6
#define KEYCARD_PUK_LEN 12

#define KEYCARD_NAME_MAX_LEN 20
#define KEYCARD_PAIRING_PASS_MAX_LEN 32

typedef struct {
  smartcard_t sc;
  secure_channel_t ch;
  apdu_t apdu;
  char name[KEYCARD_NAME_MAX_LEN + 1];
} keycard_t;

void keycard_init(keycard_t* kc);
void keycard_activate(keycard_t* kc);
void keycard_in(keycard_t* kc);
void keycard_out(keycard_t* kc);

app_err_t keycard_factoryreset(keycard_t* kc);
app_err_t keycard_read_signature(uint8_t* data, uint8_t* digest, uint8_t* out_sig);
app_err_t keycard_set_name(keycard_t* kc, const char* name);
void keycard_pairing_password_hash(uint8_t* pass, uint8_t len, uint8_t pairing[32]);

#endif
