#include <iostream>
#include <unordered_map>
#include <string>
#include <string.h>
#include "enclave_t.h"
#include "sgx_utils.h"
#include "base64.h"

std::unordered_map<std::string, std::string> user_key_map;

// enclave sk and pk (both are little endian) used for out signatures
sgx_ec256_private_t enclave_sk = {0};
sgx_ec256_public_t enclave_pk = {0};

void bytes_swap(void *bytes, size_t len)
{
    unsigned char *start, *end;
    for (start = (unsigned char *)bytes, end = start + len - 1; start < end; ++start, --end) {
        unsigned char swap = *start;
        *start = *end;
        *end = swap;
    }
}

int ecall_set_key(const char* pk, const char* nonce, uint8_t* val, uint32_t val_len, uint8_t* token, uint8_t* signature, uint32_t* tok_len, uint32_t* sig_len) {
    // char* insideVal = new char[val_len];
    // memcpy(insideVal, val, val_len);
    // const std::string keyVal = std::string(key);
    // user_key_map[keyVal] = insideVal;
    return 0;
}

int ecall_get_key(const char*pk, const char* token, uint8_t* val, uint32_t max_val_len, uint8_t* signature, uint32_t max_sig_len, uint32_t* val_len, uint32_t* sig_len) {
    // const std::string keyVal = std::string(key);
    // const std::string insideVal = user_key_map[keyVal];
    // memcpy(val, insideVal.c_str(), insideVal.length());
    return 0;
}

// returns enclave pk in Big Endian format
int ecall_get_pk(uint8_t *pubkey) {
    // transform enclave_pk to Big Endian before hashing
    uint8_t enclave_pk_be[sizeof(sgx_ec256_public_t)];
    memcpy(enclave_pk_be, &enclave_pk, sizeof(sgx_ec256_public_t));
    bytes_swap(enclave_pk_be, 32);
    bytes_swap(enclave_pk_be + 32, 32);

    memcpy(pubkey, &enclave_pk_be, sizeof(sgx_ec256_public_t));

    return SGX_SUCCESS;
}

int ecall_init() {
    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_status_t sgx_ret = sgx_ecc256_open_context(&ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        return sgx_ret;
    }

    // create pub and private signature key
    sgx_ret = sgx_ecc256_create_key_pair(&enclave_sk, &enclave_pk, ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        return sgx_ret;
    }
    sgx_ecc256_close_context(ecc_handle);

    std::string base64_pk =
        base64_encode((const unsigned char *)&enclave_pk, sizeof(sgx_ec256_public_t));
    return SGX_SUCCESS;
}


