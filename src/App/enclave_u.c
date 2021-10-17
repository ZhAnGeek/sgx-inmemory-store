#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_set_key_t {
	const char* ms_key;
	size_t ms_key_len;
	uint8_t* ms_val;
	uint32_t ms_val_len;
} ms_ecall_set_key_t;

typedef struct ms_ecall_get_key_t {
	const char* ms_key;
	size_t ms_key_len;
	uint8_t* ms_val;
	uint32_t ms_max_val_len;
	uint32_t* ms_val_len;
} ms_ecall_get_key_t;

typedef struct ms_ecall_init_t {
	int ms_retval;
} ms_ecall_init_t;

typedef struct ms_ecall_get_pk_t {
	int ms_retval;
	uint8_t* ms_pubkey;
} ms_ecall_get_pk_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_set_key(sgx_enclave_id_t eid, const char* key, uint8_t* val, uint32_t val_len)
{
	sgx_status_t status;
	ms_ecall_set_key_t ms;
	ms.ms_key = key;
	ms.ms_key_len = key ? strlen(key) + 1 : 0;
	ms.ms_val = val;
	ms.ms_val_len = val_len;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_key(sgx_enclave_id_t eid, const char* key, uint8_t* val, uint32_t max_val_len, uint32_t* val_len)
{
	sgx_status_t status;
	ms_ecall_get_key_t ms;
	ms.ms_key = key;
	ms.ms_key_len = key ? strlen(key) + 1 : 0;
	ms.ms_val = val;
	ms.ms_max_val_len = max_val_len;
	ms.ms_val_len = val_len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_pk(sgx_enclave_id_t eid, int* retval, uint8_t* pubkey)
{
	sgx_status_t status;
	ms_ecall_get_pk_t ms;
	ms.ms_pubkey = pubkey;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

