#ifndef logging_h
#define logging_h

#undef TAG
#define TAG "[Enclave] "

#include "../log-defines.h"

/*
 * `loggingf` forwards the input string to the ocall function.
 * Returns a boolean as integer:
 * 0 false/error
 * >0 true/success
 *
 * The function prototype is in "../include/log-defines.h"
 */

#endif
