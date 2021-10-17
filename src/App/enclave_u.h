#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_set_key(sgx_enclave_id_t eid, const char* pk, const char* key, uint8_t* val, uint32_t val_len);
sgx_status_t ecall_get_key(sgx_enclave_id_t eid, const char* pk, const char* key, uint8_t* val, uint32_t max_val_len, uint32_t* val_len);
sgx_status_t ecall_init(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_get_pk(sgx_enclave_id_t eid, int* retval, uint8_t* pubkey);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
