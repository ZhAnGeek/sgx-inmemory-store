#include <iostream>
#include <unordered_map>
#include <string>
#include <string.h>
#include "enclave_t.h"

std::unordered_map<std::string, std::string> user_key_map;

void ecall_set_key(const char* key, uint8_t* val, uint32_t val_len) {
    char* insideVal = new char[val_len];
    memcpy(insideVal, val, val_len);
    const std::string keyVal = std::string(key);
    user_key_map[keyVal] = insideVal;
}

void ecall_get_key(const char* key, uint8_t* val, uint32_t max_val_len, uint32_t* val_len) {
    const std::string keyVal = std::string(key);
    const std::string insideVal = user_key_map[keyVal];
    memcpy(val, insideVal.c_str(), sizeof(insideVal.c_str()));
    *val_len = sizeof(insideVal.c_str());
}

int ecall_init(const uint8_t* attestation_parameters, uint32_t ap_size, const uint8_t* cc_parameters, uint32_t ccp_size, const uint8_t* host_parameters, uint32_t hp_size, uint8_t* credentials, uint32_t credentials_max_size, uint32_t* credentials_size) {
    // TODO: init an enclave
    return 0;
}
