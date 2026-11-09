#ifndef SC_HOST_H
#define SC_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The card side of the ISO 7816 wire, scripted per test rather than emulated: the test says which
 * bytes the card answers with and which transfers fail, and reads back what the shell put on the
 * wire. There is no card state here -- a scenario that needs the card to remember something is a
 * scenario that should say so with the bytes it replies with.
 */

void hal_host_sc_reset(void);

/* The card's answers, consumed in order. A read that cannot be filled is a receiver timeout, which
 * is what the peripheral reports and what the modules turn into ERR_TXRX. */
void hal_host_sc_reply(const uint8_t* bytes, size_t len);
void hal_host_sc_reply_hex(const char* hex);
size_t hal_host_sc_unread(void);

void hal_host_sc_fail_read_after(unsigned n);
void hal_host_sc_fail_notify_after(unsigned n);
void hal_host_sc_notify_value(uint32_t value);
void hal_host_sc_refuse_send(unsigned n);
void hal_host_sc_pps_refuse(bool refuse);

/* What the shell transmitted, oldest first. */
const uint8_t* hal_host_sc_sent(void);
size_t hal_host_sc_sent_len(void);
void hal_host_sc_sent_clear(void);
unsigned hal_host_sc_send_calls(void);

/* Peripheral settings the module pushed, and the events it caused. */
unsigned hal_host_sc_timeout_count(void);
uint32_t hal_host_sc_timeout(unsigned i);
uint32_t hal_host_sc_last_timeout(void);
uint32_t hal_host_sc_blocklen(void);
uint32_t hal_host_sc_delayed_us(void);
unsigned hal_host_sc_starts(void);
unsigned hal_host_sc_stops(void);
unsigned hal_host_sc_aborts(void);

bool hal_host_sc_pps_called(void);
int hal_host_sc_pps_protocol(void);
uint32_t hal_host_sc_pps_baud(void);
uint32_t hal_host_sc_pps_freq(void);
uint8_t hal_host_sc_pps_guard(void);
uint32_t hal_host_sc_pps_timeout(void);

#endif
