#include "Enclave_t.h"

#include "sgx_error.h"
#include "sgx_mage.h"
#include "sgx_report.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

#include <string.h>

uint32_t enclave_create_report(const sgx_target_info_t *p_qe3_target, sgx_report_t *p_report)
{
    sgx_report_data_t report_data = {0};
    return sgx_create_report(p_qe3_target, &report_data, p_report);
}

uint32_t enclave_check_derived_measurement(const uint8_t *mr_bytes, uint32_t *is_match)
{
    if (mr_bytes == NULL || is_match == NULL) {
        return 1;
    }

    *is_match = 0;
    volatile uint8_t *mage_buf = get_sgx_mage_sec_buf_addr();
    volatile uint8_t mage_anchor = mage_buf[0];
    (void)mage_anchor;
    const uint64_t mage_size = sgx_mage_get_size();
    sgx_measurement_t measurement = {};
    for (uint64_t idx = 0; idx < mage_size; ++idx) {
        if (sgx_mage_derive_measurement(idx, &measurement) != SGX_SUCCESS) {
            continue;
        }
        if (memcmp(measurement.m, mr_bytes, sizeof(measurement.m)) == 0) {
            *is_match = 1;
            return 0;
        }
    }
    return 0;
}
