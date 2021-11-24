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

int ecall_set_key(const char* pk, const char* nonce, uint8_t* val, uint32_t val_len, uint8_t* signature, uint8_t* token, uint32_t* sig_len, uint32_t* tok_len) {
    sgx_ec256_public_t client_pk = {0};

    uint8_t *pk_bytes = (uint8_t *)pk;
    bytes_swap(pk_bytes, 32);
    bytes_swap(pk_bytes + 32, 32);
    memcpy(&client_pk, pk_bytes, sizeof(sgx_ec256_public_t));

    sgx_ec256_dh_shared_t shared_dhkey;

    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_ecc256_open_context(&ecc_handle);
    int sgx_ret = sgx_ecc256_compute_shared_dhkey(&enclave_sk, &client_pk, &shared_dhkey, ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        return sgx_ret;
    }
    sgx_ecc256_close_context(ecc_handle);
    bytes_swap(&shared_dhkey, 32);

    sgx_aes_gcm_128bit_key_t key;
    memcpy(key, &shared_dhkey, sizeof(sgx_aes_gcm_128bit_key_t));

    uint8_t *cipher = val;
    uint32_t cipher_len = val_len;

    uint32_t needed_size = cipher_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    // need one byte more for string terminator
    char plain[needed_size + 1];
    plain[needed_size] = '\0';
    
    // encrypt
    std::string ptk = "hello_world";
    sgx_rijndael128GCM_encrypt(&key, (uint8_t *)ptk.c_str(), ptk.length(),
        token + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, cipher, SGX_AESGCM_IV_SIZE, NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *)(token + SGX_AESGCM_IV_SIZE));

    bytes_swap(&key, 16)
    // encrypt
    sgx_rijndael128GCM_encrypt(&key, (uint8_t *)ptk.c_str(), ptk.length(),
        signature + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, cipher, SGX_AESGCM_IV_SIZE, NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *)(signature + SGX_AESGCM_IV_SIZE));

    // sgx_ret = sgx_rijndael128GCM_decrypt(&key,
    //     cipher + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,          /* cipher */
    //     needed_size, (uint8_t *)plain,                              /* plain out */
    //     cipher, SGX_AESGCM_IV_SIZE,                                 /* nonce */
    //     NULL, 0,                                                    /* aad */
    //     (sgx_aes_gcm_128bit_tag_t *)(cipher + SGX_AESGCM_IV_SIZE)); /* tag */
    // if (sgx_ret != SGX_SUCCESS) {
    //     return sgx_ret;
    // }

    // needed_size = cipher_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    // // need one byte more for string terminator
    // char plain_token[needed_size + 1];
    // plain_token[needed_size] = '\0';

    // unsigned char plain_token_rand[32];
    // sgx_read_rand((unsigned char*)&plain_token_rand, 32);
    // char plain_token[32];
    // memcpy(plain_token, plain_token_rand, 32);

    // const std::string ptk = std::string(plain_token, plain_token + 32);
    // user_key_map[ptk] = std::string(plain, plain + needed_size); // store

    // // create buffer
    // uint32_t ptk_cipher_len = ptk.length() + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    // uint8_t etk_nonce[SGX_AESGCM_IV_SIZE];
    // // gen rnd iv
    // sgx_read_rand((unsigned char*)&etk_nonce, SGX_AESGCM_IV_SIZE);

    // // encrypt
    // sgx_rijndael128GCM_encrypt(&key, (uint8_t *)ptk.c_str(), ptk.length(),
    //     token + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, etk_nonce, SGX_AESGCM_IV_SIZE, NULL, 0,
    //     (sgx_aes_gcm_128bit_tag_t *)(token + SGX_AESGCM_IV_SIZE));
    return SGX_SUCCESS;
}

int ecall_get_key(const char*pk, const char* token, uint8_t* val, uint32_t max_val_len, uint8_t* signature, uint32_t max_sig_len, uint32_t* val_len, uint32_t* sig_len) {
    sgx_ec256_public_t client_pk = {0};

    uint8_t *pk_bytes = (uint8_t *)pk;
    bytes_swap(pk_bytes, 32);
    bytes_swap(pk_bytes + 32, 32);
    memcpy(&client_pk, pk_bytes, sizeof(sgx_ec256_public_t));

    sgx_ec256_dh_shared_t shared_dhkey;

    sgx_ecc_state_handle_t ecc_handle = NULL;
    sgx_ecc256_open_context(&ecc_handle);
    int sgx_ret = sgx_ecc256_compute_shared_dhkey(&enclave_sk, &client_pk, &shared_dhkey, ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        return sgx_ret;
    }
    sgx_ecc256_close_context(ecc_handle);
    bytes_swap(&shared_dhkey, 32);

    sgx_sha256_hash_t h;
    sgx_sha256_msg((const uint8_t *)&shared_dhkey, sizeof(sgx_ec256_dh_shared_t), (sgx_sha256_hash_t *)&h);

    sgx_aes_gcm_128bit_key_t key;
    memcpy(key, h, sizeof(sgx_aes_gcm_128bit_key_t));

    std::string _cipher = base64_decode(token);
    uint8_t *cipher = (uint8_t *)_cipher.c_str();
    int cipher_len = _cipher.size();

    uint32_t needed_size = cipher_len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    // need one byte more for string terminator
    char plain[needed_size + 1];
    plain[needed_size] = '\0';

    // decrypt
    sgx_ret = sgx_rijndael128GCM_decrypt(&key,
        cipher + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE,          /* cipher */
        needed_size, (uint8_t *)plain,                              /* plain out */
        cipher, SGX_AESGCM_IV_SIZE,                                 /* nonce */
        NULL, 0,                                                    /* aad */
        (sgx_aes_gcm_128bit_tag_t *)(cipher + SGX_AESGCM_IV_SIZE)); /* tag */
    if (sgx_ret != SGX_SUCCESS) {
        return sgx_ret;
    }
    
    const std::string keyVal = std::string(plain);
    const std::string insideVal = user_key_map[plain];

    // create buffer
    uint32_t ptv_cipher_len = insideVal.length() + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    uint8_t ptv_token[ptv_cipher_len];
    // gen rnd iv
    sgx_read_rand(ptv_token, SGX_AESGCM_IV_SIZE);

    // encrypt
    sgx_rijndael128GCM_encrypt(&key, (uint8_t *)insideVal.c_str(), insideVal.length(),
        ptv_token + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, ptv_token, SGX_AESGCM_IV_SIZE, NULL, 0,
        (sgx_aes_gcm_128bit_tag_t *)(ptv_token + SGX_AESGCM_IV_SIZE));
    memcpy(val, ptv_token, ptv_cipher_len); // ret token
    return SGX_SUCCESS;
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


