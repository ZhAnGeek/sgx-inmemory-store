#include "common-sgxcclib.h"

#include <unistd.h>        // access

#include "check-sgx-error.h"
#include "enclave_u.h"  //ecall_init, ...
#include "logging.h"

int sgxcc_create_enclave(sgx_enclave_id_t* eid,
    const char* enclave_file,
    uint8_t* attestation_parameters,
    uint32_t ap_size,
    uint8_t* cc_parameters,
    uint32_t ccp_size,
    uint8_t* host_parameters,
    uint32_t hp_size,
    uint8_t* credentials,
    uint32_t credentials_max_size,
    uint32_t* credentials_size)
{
    if (access(enclave_file, F_OK) == -1)
    {
        LOG_ERROR("Lib: enclave file does not exist! %s", enclave_file);
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_launch_token_t token = {0};
    int updated = 0;

    int ret = sgx_create_enclave(enclave_file, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    CHECK_SGX_ERROR_AND_RETURN_ON_ERROR(ret)

    int enclave_ret = SGX_ERROR_UNEXPECTED;
    ret = ecall_init(*eid, &enclave_ret, attestation_parameters, ap_size, cc_parameters, ccp_size,
        host_parameters, hp_size, credentials, credentials_max_size, credentials_size);
    CHECK_SGX_ERROR_AND_RETURN_ON_ERROR(ret)
    CHECK_SGX_ERROR_AND_RETURN_ON_ERROR(enclave_ret)

    return SGX_SUCCESS;
}

