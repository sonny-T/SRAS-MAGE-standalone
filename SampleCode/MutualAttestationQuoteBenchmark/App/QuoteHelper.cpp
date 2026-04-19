#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <fstream>
#include <iterator>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_ql_quote.h"
#include "sgx_qve_header.h"
#include "sgx_quote_3.h"
#include "sgx_report.h"

#ifndef __sgx_ql_qve_collateral_t
#define __sgx_ql_qve_collateral_t
typedef struct _sgx_ql_qve_collateral_t {
    union {
        uint32_t version;
        struct {
            uint16_t major_version;
            uint16_t minor_version;
        };
    };
    uint32_t tee_type;
    char *pck_crl_issuer_chain;
    uint32_t pck_crl_issuer_chain_size;
    char *root_ca_crl;
    uint32_t root_ca_crl_size;
    char *pck_crl;
    uint32_t pck_crl_size;
    char *tcb_info_issuer_chain;
    uint32_t tcb_info_issuer_chain_size;
    char *tcb_info;
    uint32_t tcb_info_size;
    char *qe_identity_issuer_chain;
    uint32_t qe_identity_issuer_chain_size;
    char *qe_identity;
    uint32_t qe_identity_size;
} sgx_ql_qve_collateral_t;
#endif

extern "C" quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data);

extern "C" quote3_error_t sgx_ql_get_quote_verification_collateral(
    const uint8_t *fmspc,
    uint16_t fmspc_size,
    const char *pck_ca,
    sgx_ql_qve_collateral_t **pp_quote_collateral);

extern "C" quote3_error_t sgx_ql_free_quote_verification_collateral(
    sgx_ql_qve_collateral_t *p_quote_collateral);

namespace {

enum class command_t {
    kNone,
    kTargetInfo,
    kQuote,
    kVerify,
    kServer,
};

struct options_t {
    command_t command = command_t::kNone;
    std::string report_path;
    std::string quote_path;
    std::string output_path;
    std::string fmspc;
    std::string pck_ca = "platform";
};

struct cached_collateral_t {
    sgx_ql_qve_collateral_t *collateral;
    bool dcap_allocated;
};

std::map<std::string, cached_collateral_t> g_collateral_cache;
std::string g_last_response_details;
bool g_qe_target_info_initialized = false;
sgx_target_info_t g_cached_target_info = {0};
uint32_t g_cached_quote_size = 0;

const uint32_t kCollateralCacheMagic = 0x4d434f4c;  // "LCOM", little-endian marker.
const uint32_t kCollateralCacheVersion = 1;

uint64_t monotonic_now_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

double elapsed_ms(uint64_t start_ns, uint64_t end_ns)
{
    return end_ns > start_ns ? static_cast<double>(end_ns - start_ns) / 1000000.0 : 0.0;
}

bool parse_hex_byte(char ch, uint8_t *value)
{
    if (ch >= '0' && ch <= '9') {
        *value = static_cast<uint8_t>(ch - '0');
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        *value = static_cast<uint8_t>(ch - 'a' + 10);
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        *value = static_cast<uint8_t>(ch - 'A' + 10);
        return true;
    }
    return false;
}

bool hex_to_bytes(const std::string &hex, std::vector<uint8_t> *bytes)
{
    if (hex.size() % 2U != 0U) {
        return false;
    }
    bytes->clear();
    bytes->reserve(hex.size() / 2U);
    for (size_t idx = 0; idx < hex.size(); idx += 2U) {
        uint8_t hi = 0;
        uint8_t lo = 0;
        if (!parse_hex_byte(hex[idx], &hi) || !parse_hex_byte(hex[idx + 1U], &lo)) {
            return false;
        }
        bytes->push_back(static_cast<uint8_t>((hi << 4U) | lo));
    }
    return true;
}

std::string bytes_to_hex(const uint8_t *data, size_t size)
{
    static const char *kHex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2U);
    for (size_t idx = 0; idx < size; ++idx) {
        out.push_back(kHex[(data[idx] >> 4U) & 0x0f]);
        out.push_back(kHex[data[idx] & 0x0f]);
    }
    return out;
}

bool write_atomic_file(const std::string &path, const uint8_t *data, size_t size)
{
    const std::string temp_path = path + ".tmp";
    FILE *handle = fopen(temp_path.c_str(), "wb");
    if (handle == NULL) {
        return false;
    }
    const bool ok = fwrite(data, 1, size, handle) == size && fflush(handle) == 0;
    const int close_ret = fclose(handle);
    if (!ok || close_ret != 0) {
        unlink(temp_path.c_str());
        return false;
    }
    return rename(temp_path.c_str(), path.c_str()) == 0;
}

bool write_atomic_text(const std::string &path, const std::string &payload)
{
    return write_atomic_file(path, reinterpret_cast<const uint8_t *>(payload.data()), payload.size());
}

bool read_file(const std::string &path, std::vector<uint8_t> *buffer)
{
    std::ifstream input(path.c_str(), std::ios::binary);
    if (!input) {
        return false;
    }
    buffer->assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return input.good() || input.eof();
}

std::string get_collateral_cache_dir()
{
    const char *cache_dir = getenv("COLLATERAL_CACHE_DIR");
    return cache_dir == NULL ? std::string() : std::string(cache_dir);
}

std::string collateral_cache_path(const std::string &cache_key)
{
    std::string cache_dir = get_collateral_cache_dir();
    if (cache_dir.empty()) {
        return std::string();
    }
    if (!cache_dir.empty() && cache_dir[cache_dir.size() - 1U] != '/') {
        cache_dir += "/";
    }
    std::string filename = cache_key;
    for (size_t idx = 0; idx < filename.size(); ++idx) {
        if (filename[idx] == ':' || filename[idx] == '/') {
            filename[idx] = '_';
        }
    }
    return cache_dir + filename + ".bin";
}

bool read_exact(FILE *handle, void *data, size_t size)
{
    return size == 0U || fread(data, 1, size, handle) == size;
}

bool write_exact(FILE *handle, const void *data, size_t size)
{
    return size == 0U || fwrite(data, 1, size, handle) == size;
}

bool read_u32(FILE *handle, uint32_t *value)
{
    return read_exact(handle, value, sizeof(*value));
}

bool write_u32(FILE *handle, uint32_t value)
{
    return write_exact(handle, &value, sizeof(value));
}

void free_file_collateral(sgx_ql_qve_collateral_t *collateral)
{
    if (collateral == NULL) {
        return;
    }
    free(collateral->pck_crl_issuer_chain);
    free(collateral->root_ca_crl);
    free(collateral->pck_crl);
    free(collateral->tcb_info_issuer_chain);
    free(collateral->tcb_info);
    free(collateral->qe_identity_issuer_chain);
    free(collateral->qe_identity);
    free(collateral);
}

bool read_blob(FILE *handle, char **data, uint32_t *size)
{
    uint32_t blob_size = 0;
    if (!read_u32(handle, &blob_size)) {
        return false;
    }
    char *blob = NULL;
    if (blob_size > 0U) {
        blob = static_cast<char *>(calloc(static_cast<size_t>(blob_size) + 1U, 1));
        if (blob == NULL || !read_exact(handle, blob, blob_size)) {
            free(blob);
            return false;
        }
    }
    *data = blob;
    *size = blob_size;
    return true;
}

bool write_blob(FILE *handle, const char *data, uint32_t size)
{
    if (!write_u32(handle, size)) {
        return false;
    }
    return size == 0U || (data != NULL && write_exact(handle, data, size));
}

bool load_collateral_from_file(const std::string &path, sgx_ql_qve_collateral_t **collateral)
{
    FILE *handle = fopen(path.c_str(), "rb");
    if (handle == NULL) {
        return false;
    }

    bool ok = false;
    sgx_ql_qve_collateral_t *loaded = static_cast<sgx_ql_qve_collateral_t *>(calloc(1, sizeof(*loaded)));
    uint32_t magic = 0;
    uint32_t cache_version = 0;
    uint32_t major_version = 0;
    uint32_t minor_version = 0;
    uint32_t tee_type = 0;
    if (loaded != NULL &&
        read_u32(handle, &magic) &&
        read_u32(handle, &cache_version) &&
        magic == kCollateralCacheMagic &&
        cache_version == kCollateralCacheVersion &&
        read_u32(handle, &major_version) &&
        read_u32(handle, &minor_version) &&
        read_u32(handle, &tee_type)) {
        loaded->major_version = static_cast<uint16_t>(major_version);
        loaded->minor_version = static_cast<uint16_t>(minor_version);
        loaded->tee_type = tee_type;
        ok = read_blob(handle, &loaded->pck_crl_issuer_chain, &loaded->pck_crl_issuer_chain_size) &&
             read_blob(handle, &loaded->root_ca_crl, &loaded->root_ca_crl_size) &&
             read_blob(handle, &loaded->pck_crl, &loaded->pck_crl_size) &&
             read_blob(handle, &loaded->tcb_info_issuer_chain, &loaded->tcb_info_issuer_chain_size) &&
             read_blob(handle, &loaded->tcb_info, &loaded->tcb_info_size) &&
             read_blob(handle, &loaded->qe_identity_issuer_chain, &loaded->qe_identity_issuer_chain_size) &&
             read_blob(handle, &loaded->qe_identity, &loaded->qe_identity_size);
    }

    fclose(handle);
    if (!ok) {
        free_file_collateral(loaded);
        return false;
    }
    *collateral = loaded;
    return true;
}

bool write_collateral_to_file(const std::string &path, const sgx_ql_qve_collateral_t *collateral)
{
    if (path.empty() || collateral == NULL) {
        return false;
    }
    const std::string temp_path = path + ".tmp." + std::to_string(static_cast<long long>(getpid()));
    FILE *handle = fopen(temp_path.c_str(), "wb");
    if (handle == NULL) {
        return false;
    }

    const bool ok = write_u32(handle, kCollateralCacheMagic) &&
                    write_u32(handle, kCollateralCacheVersion) &&
                    write_u32(handle, collateral->major_version) &&
                    write_u32(handle, collateral->minor_version) &&
                    write_u32(handle, collateral->tee_type) &&
                    write_blob(handle, collateral->pck_crl_issuer_chain, collateral->pck_crl_issuer_chain_size) &&
                    write_blob(handle, collateral->root_ca_crl, collateral->root_ca_crl_size) &&
                    write_blob(handle, collateral->pck_crl, collateral->pck_crl_size) &&
                    write_blob(handle, collateral->tcb_info_issuer_chain, collateral->tcb_info_issuer_chain_size) &&
                    write_blob(handle, collateral->tcb_info, collateral->tcb_info_size) &&
                    write_blob(handle, collateral->qe_identity_issuer_chain, collateral->qe_identity_issuer_chain_size) &&
                    write_blob(handle, collateral->qe_identity, collateral->qe_identity_size) &&
                    fflush(handle) == 0;
    const int close_ret = fclose(handle);
    if (!ok || close_ret != 0) {
        unlink(temp_path.c_str());
        return false;
    }
    return rename(temp_path.c_str(), path.c_str()) == 0 || errno == EEXIST;
}

bool is_advisory_ok(sgx_ql_qv_result_t result)
{
    switch (result) {
    case SGX_QL_QV_RESULT_OK:
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        return true;
    default:
        return false;
    }
}

bool extract_mrenclave(const std::vector<uint8_t> &quote, std::string *mrenclave_hex)
{
    if (quote.size() < sizeof(sgx_quote3_t)) {
        return false;
    }
    const sgx_quote3_t *parsed = reinterpret_cast<const sgx_quote3_t *>(quote.data());
    *mrenclave_hex = bytes_to_hex(parsed->report_body.mr_enclave.m, sizeof(parsed->report_body.mr_enclave.m));
    return true;
}

std::vector<std::string> split_tabs(const std::string &line)
{
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= line.size()) {
        const size_t pos = line.find('\t', start);
        if (pos == std::string::npos) {
            parts.push_back(line.substr(start));
            break;
        }
        parts.push_back(line.substr(start, pos - start));
        start = pos + 1U;
    }
    return parts;
}

bool parse_options(int argc, char *argv[], options_t *options)
{
    static const struct option kLongOptions[] = {
        {"server", no_argument, NULL, 's'},
        {"command", required_argument, NULL, 'c'},
        {"report", required_argument, NULL, 'r'},
        {"quote", required_argument, NULL, 'q'},
        {"out", required_argument, NULL, 'o'},
        {"fmspc", required_argument, NULL, 'f'},
        {"pck-ca", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0},
    };

    int opt = 0;
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "sc:r:q:o:f:p:", kLongOptions, NULL)) != -1) {
        switch (opt) {
        case 's':
            options->command = command_t::kServer;
            break;
        case 'c':
            if (strcmp(optarg, "target-info") == 0) {
                options->command = command_t::kTargetInfo;
            } else if (strcmp(optarg, "quote") == 0) {
                options->command = command_t::kQuote;
            } else if (strcmp(optarg, "verify") == 0) {
                options->command = command_t::kVerify;
            } else {
                return false;
            }
            break;
        case 'r':
            options->report_path = optarg;
            break;
        case 'q':
            options->quote_path = optarg;
            break;
        case 'o':
            options->output_path = optarg;
            break;
        case 'f':
            options->fmspc = optarg;
            break;
        case 'p':
            options->pck_ca = optarg;
            break;
        default:
            return false;
        }
    }

    if (options->command == command_t::kServer) {
        return true;
    }
    if (options->command == command_t::kNone || options->output_path.empty()) {
        return false;
    }
    if (options->command == command_t::kQuote && options->report_path.empty()) {
        return false;
    }
    if (options->command == command_t::kVerify && (options->quote_path.empty() || options->fmspc.size() != 12U)) {
        return false;
    }
    return true;
}

void print_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s --server\n"
            "usage: %s --command target-info --out FILE\n"
            "       %s --command quote --report FILE --out FILE\n"
            "       %s --command verify --quote FILE --fmspc HEX12 [--pck-ca platform|processor] --out FILE\n",
            program,
            program,
            program,
            program);
}

int run_target_info(const options_t &options)
{
    if (!g_qe_target_info_initialized) {
        quote3_error_t ret = sgx_qe_get_target_info(&g_cached_target_info);
        if (ret != SGX_QL_SUCCESS) {
            fprintf(stderr, "sgx_qe_get_target_info failed: 0x%04x\n", ret);
            return EXIT_FAILURE;
        }
        g_qe_target_info_initialized = true;
    }
    return write_atomic_file(options.output_path,
                             reinterpret_cast<const uint8_t *>(&g_cached_target_info),
                             sizeof(g_cached_target_info))
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}

int run_quote(const options_t &options)
{
    g_last_response_details.clear();
    const uint64_t read_report_start_ns = monotonic_now_ns();
    std::vector<uint8_t> report_bytes;
    if (!read_file(options.report_path, &report_bytes) || report_bytes.size() != sizeof(sgx_report_t)) {
        fprintf(stderr, "failed to read sgx report\n");
        return EXIT_FAILURE;
    }
    const double read_report_ms = elapsed_ms(read_report_start_ns, monotonic_now_ns());
    const sgx_report_t *report = reinterpret_cast<const sgx_report_t *>(report_bytes.data());

    const uint64_t qe_target_info_start_ns = monotonic_now_ns();
    if (!g_qe_target_info_initialized) {
        // Standalone quote mode has not run target-info in this process yet.
        // Server mode normally skips this because app already requested target-info
        // before creating the enclave report.
        sgx_target_info_t unused_target_info = {0};
        quote3_error_t ret = sgx_qe_get_target_info(&unused_target_info);
        if (ret != SGX_QL_SUCCESS) {
            fprintf(stderr, "sgx_qe_get_target_info failed before quote: 0x%04x\n", ret);
            return EXIT_FAILURE;
        }
        g_qe_target_info_initialized = true;
    }
    const double qe_target_info_ms = elapsed_ms(qe_target_info_start_ns, monotonic_now_ns());

    const uint64_t quote_size_start_ns = monotonic_now_ns();
    if (g_cached_quote_size == 0) {
        quote3_error_t ret = sgx_qe_get_quote_size(&g_cached_quote_size);
        if (ret != SGX_QL_SUCCESS) {
            fprintf(stderr, "sgx_qe_get_quote_size failed: 0x%04x\n", ret);
            return EXIT_FAILURE;
        }
    }
    const double quote_size_ms = elapsed_ms(quote_size_start_ns, monotonic_now_ns());

    std::vector<uint8_t> quote(g_cached_quote_size, 0);
    const uint64_t get_quote_start_ns = monotonic_now_ns();
    quote3_error_t ret = sgx_qe_get_quote(report, g_cached_quote_size, quote.data());
    if (ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "sgx_qe_get_quote failed: 0x%04x\n", ret);
        return EXIT_FAILURE;
    }
    const double get_quote_ms = elapsed_ms(get_quote_start_ns, monotonic_now_ns());

    const uint64_t write_quote_start_ns = monotonic_now_ns();
    const bool wrote_quote = write_atomic_file(options.output_path, quote.data(), quote.size());
    const double write_quote_ms = elapsed_ms(write_quote_start_ns, monotonic_now_ns());

    std::ostringstream details;
    details.setf(std::ios::fixed);
    details.precision(3);
    details << " read_report_ms=" << read_report_ms
            << " qe_target_info_ms=" << qe_target_info_ms
            << " quote_size_ms=" << quote_size_ms
            << " get_quote_ms=" << get_quote_ms
            << " write_quote_ms=" << write_quote_ms;
    g_last_response_details = details.str();

    return wrote_quote ? EXIT_SUCCESS : EXIT_FAILURE;
}

bool get_cached_collateral(const options_t &options, sgx_ql_qve_collateral_t **collateral)
{
    const std::string cache_key = options.fmspc + ":" + options.pck_ca;
    std::map<std::string, cached_collateral_t>::iterator found = g_collateral_cache.find(cache_key);
    if (found != g_collateral_cache.end()) {
        *collateral = found->second.collateral;
        return true;
    }

    const std::string file_cache_path = collateral_cache_path(cache_key);
    if (!file_cache_path.empty()) {
        sgx_ql_qve_collateral_t *file_collateral = NULL;
        if (load_collateral_from_file(file_cache_path, &file_collateral)) {
            cached_collateral_t cached = {file_collateral, false};
            g_collateral_cache[cache_key] = cached;
            *collateral = file_collateral;
            return true;
        }
    }

    std::vector<uint8_t> fmspc_bytes;
    if (!hex_to_bytes(options.fmspc, &fmspc_bytes)) {
        fprintf(stderr, "invalid fmspc hex string\n");
        return false;
    }

    sgx_ql_qve_collateral_t *new_collateral = NULL;
    quote3_error_t ql_ret = sgx_ql_get_quote_verification_collateral(
        fmspc_bytes.data(),
        static_cast<uint16_t>(fmspc_bytes.size()),
        options.pck_ca.c_str(),
        &new_collateral);
    if (ql_ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "sgx_ql_get_quote_verification_collateral failed: 0x%04x\n", ql_ret);
        return false;
    }

    cached_collateral_t cached = {new_collateral, true};
    g_collateral_cache[cache_key] = cached;
    if (!file_cache_path.empty()) {
        write_collateral_to_file(file_cache_path, new_collateral);
    }
    *collateral = new_collateral;
    return true;
}

void free_collateral_cache()
{
    for (std::map<std::string, cached_collateral_t>::iterator it = g_collateral_cache.begin();
         it != g_collateral_cache.end();
         ++it) {
        if (it->second.dcap_allocated) {
            sgx_ql_free_quote_verification_collateral(it->second.collateral);
        } else {
            free_file_collateral(it->second.collateral);
        }
    }
    g_collateral_cache.clear();
}

int run_verify(const options_t &options)
{
    g_last_response_details.clear();
    const uint64_t read_quote_start_ns = monotonic_now_ns();
    std::vector<uint8_t> quote;
    if (!read_file(options.quote_path, &quote)) {
        fprintf(stderr, "failed to read quote\n");
        return EXIT_FAILURE;
    }
    const double read_quote_ms = elapsed_ms(read_quote_start_ns, monotonic_now_ns());

    const uint64_t parse_quote_start_ns = monotonic_now_ns();
    std::string mrenclave_hex;
    if (!extract_mrenclave(quote, &mrenclave_hex)) {
        fprintf(stderr, "failed to parse quote mrenclave\n");
        return EXIT_FAILURE;
    }
    const double parse_quote_ms = elapsed_ms(parse_quote_start_ns, monotonic_now_ns());

    sgx_ql_qve_collateral_t *collateral = NULL;
    const uint64_t collateral_start_ns = monotonic_now_ns();
    if (!get_cached_collateral(options, &collateral)) {
        return EXIT_FAILURE;
    }
    const double collateral_ms = elapsed_ms(collateral_start_ns, monotonic_now_ns());

    time_t current_time = time(NULL);
    uint32_t collateral_expiration_status = 0;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    const uint64_t qv_verify_start_ns = monotonic_now_ns();
    quote3_error_t ql_ret = sgx_qv_verify_quote(
        quote.data(),
        static_cast<uint32_t>(quote.size()),
        collateral,
        current_time,
        &collateral_expiration_status,
        &qv_result,
        NULL,
        0,
        NULL);
    const double qv_verify_ms = elapsed_ms(qv_verify_start_ns, monotonic_now_ns());

    const bool verified = (ql_ret == SGX_QL_SUCCESS) && is_advisory_ok(qv_result);
    char buffer[512];
    snprintf(buffer,
             sizeof(buffer),
             "{\n"
             "  \"verified\": %s,\n"
             "  \"mrenclave\": \"%s\",\n"
             "  \"verify_ret\": %u,\n"
             "  \"qv_result\": %d,\n"
             "  \"collateral_expiration_status\": %u\n"
             "}\n",
             verified ? "true" : "false",
             mrenclave_hex.c_str(),
             static_cast<unsigned>(ql_ret),
             static_cast<int>(qv_result),
             collateral_expiration_status);
    const uint64_t write_verify_start_ns = monotonic_now_ns();
    const bool wrote_verify = write_atomic_text(options.output_path, std::string(buffer));
    const double write_verify_ms = elapsed_ms(write_verify_start_ns, monotonic_now_ns());

    std::ostringstream details;
    details.setf(std::ios::fixed);
    details.precision(3);
    details << " read_quote_ms=" << read_quote_ms
            << " parse_quote_ms=" << parse_quote_ms
            << " collateral_ms=" << collateral_ms
            << " qv_verify_ms=" << qv_verify_ms
            << " write_verify_ms=" << write_verify_ms;
    g_last_response_details = details.str();

    return wrote_verify ? (verified ? EXIT_SUCCESS : EXIT_FAILURE) : EXIT_FAILURE;
}

int run_server()
{
    std::string line;
    while (std::getline(std::cin, line)) {
        std::vector<std::string> parts = split_tabs(line);
        if (parts.empty()) {
            printf("ERR empty command\n");
            fflush(stdout);
            continue;
        }
        if (parts[0] == "exit") {
            printf("OK\n");
            fflush(stdout);
            break;
        }

        options_t command_options;
        int ret = EXIT_FAILURE;
        if (parts[0] == "target-info" && parts.size() == 2U) {
            command_options.command = command_t::kTargetInfo;
            command_options.output_path = parts[1];
            ret = run_target_info(command_options);
        } else if (parts[0] == "quote" && parts.size() == 3U) {
            command_options.command = command_t::kQuote;
            command_options.report_path = parts[1];
            command_options.output_path = parts[2];
            ret = run_quote(command_options);
        } else if (parts[0] == "verify" && parts.size() == 5U) {
            command_options.command = command_t::kVerify;
            command_options.quote_path = parts[1];
            command_options.fmspc = parts[2];
            command_options.pck_ca = parts[3];
            command_options.output_path = parts[4];
            ret = run_verify(command_options);
        } else {
            fprintf(stderr, "invalid server command: %s\n", line.c_str());
        }

        if (ret == EXIT_SUCCESS) {
            printf("OK%s\n", g_last_response_details.c_str());
        } else {
            printf("ERR\n");
        }
        fflush(stdout);
    }

    free_collateral_cache();
    return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char *argv[])
{
    options_t options;
    if (!parse_options(argc, argv, &options)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    switch (options.command) {
    case command_t::kServer:
        return run_server();
    case command_t::kTargetInfo:
        return run_target_info(options);
    case command_t::kQuote:
        return run_quote(options);
    case command_t::kVerify:
        return run_verify(options);
    default:
        free_collateral_cache();
        return EXIT_FAILURE;
    }
}
