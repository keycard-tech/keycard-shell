#ifndef CORE_OPENPGP_H
#define CORE_OPENPGP_H

#include "error.h"

/*
 * Run the dedicated OpenPGP flow using the Shell-owned derivation policy.
 *
 * The host/request does not select the Keycard derivation path.
 */
app_err_t core_openpgp_run(void);

#endif
