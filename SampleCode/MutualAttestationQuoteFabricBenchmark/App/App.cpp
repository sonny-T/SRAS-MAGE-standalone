#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "Enclave_u.h"
#include "sgx_quote_3.h"
#include "sgx_report.h"
#include "sgx_urts.h"

namespace {

struct options_t {
    uint32_t party_id = 0;
    uint32_t parties = 0;
    uint32_t timeout_sec = 60;
    std::string quote_dir;
    std::string result_dir;
    std::string fmspc;
    std::string pck_ca = "platform";
    std::string helper_path = "./quote_helper";
    std::string fabric_address;
    std::string fabric_helper_path = "./fabric_quote_helper.py";
    std::string fabric_proto_dir = "./rpe_conn";
    std::string fabric_run_id;
    std::string fabric_poll_interval = "0.05";
    bool warmup_quote = false;
};

struct verify_summary_t {
    uint32_t verified_quotes = 0;
    uint32_t identity_matches = 0;
    std::string local_mrenclave_hex;
};

struct peer_timing_t {
    uint32_t party_id = 0;
    double quote_verify_ms = 0.0;
    double verify_read_quote_ms = 0.0;
    double verify_parse_quote_ms = 0.0;
    double verify_collateral_ms = 0.0;
    double verify_qv_verify_ms = 0.0;
    double verify_write_json_ms = 0.0;
    double identity_check_ms = 0.0;
    bool quote_verified = false;
    bool identity_matched = false;
};

struct timing_summary_t {
    double warmup_quote_ms = 0.0;
    double target_info_ms = 0.0;
    double create_report_ms = 0.0;
    double quote_generation_ms = 0.0;
    double quote_read_report_ms = 0.0;
    double quote_qe_target_info_ms = 0.0;
    double quote_size_ms = 0.0;
    double quote_get_quote_ms = 0.0;
    double quote_write_quote_ms = 0.0;
    double local_quote_total_ms = 0.0;
    double wait_all_quotes_ms = 0.0;
    double quote_verification_total_ms = 0.0;
    double identity_check_total_ms = 0.0;
    std::vector<peer_timing_t> peer_timings;
};

struct helper_session_t {
    pid_t pid = -1;
    FILE *request = NULL;
    FILE *response = NULL;

    bool start(const std::string &helper_path)
    {
        int to_child[2] = {-1, -1};
        int from_child[2] = {-1, -1};
        if (pipe(to_child) != 0 || pipe(from_child) != 0) {
            return false;
        }

        pid = fork();
        if (pid < 0) {
            close(to_child[0]);
            close(to_child[1]);
            close(from_child[0]);
            close(from_child[1]);
            return false;
        }
        if (pid == 0) {
            dup2(to_child[0], STDIN_FILENO);
            dup2(from_child[1], STDOUT_FILENO);
            close(to_child[0]);
            close(to_child[1]);
            close(from_child[0]);
            close(from_child[1]);
            setenv("LD_LIBRARY_PATH", "/usr/lib/x86_64-linux-gnu", 1);
            execl(helper_path.c_str(), helper_path.c_str(), "--server", (char *)NULL);
            _exit(127);
        }

        close(to_child[0]);
        close(from_child[1]);
        request = fdopen(to_child[1], "w");
        response = fdopen(from_child[0], "r");
        if (request == NULL || response == NULL) {
            stop();
            return false;
        }
        setvbuf(request, NULL, _IONBF, 0);
        return true;
    }

    bool run(const std::vector<std::string> &parts, std::string *response_line = NULL)
    {
        if (request == NULL || response == NULL || parts.empty()) {
            return false;
        }
        for (size_t idx = 0; idx < parts.size(); ++idx) {
            if (parts[idx].find('\t') != std::string::npos || parts[idx].find('\n') != std::string::npos) {
                return false;
            }
            if (idx != 0) {
                fputc('\t', request);
            }
            fputs(parts[idx].c_str(), request);
        }
        fputc('\n', request);
        fflush(request);

        char buffer[128] = {0};
        if (fgets(buffer, sizeof(buffer), response) == NULL) {
            return false;
        }
        if (response_line != NULL) {
            *response_line = buffer;
            while (!response_line->empty() &&
                   (response_line->back() == '\n' || response_line->back() == '\r')) {
                response_line->resize(response_line->size() - 1U);
            }
        }
        return strncmp(buffer, "OK", 2) == 0;
    }

    void stop()
    {
        if (request != NULL && response != NULL) {
            fputs("exit\n", request);
            fflush(request);
            char buffer[128] = {0};
            char *ignored = fgets(buffer, sizeof(buffer), response);
            (void)ignored;
        }
        if (request != NULL) {
            fclose(request);
            request = NULL;
        }
        if (response != NULL) {
            fclose(response);
            response = NULL;
        }
        if (pid > 0) {
            int status = 0;
            (void)waitpid(pid, &status, 0);
            pid = -1;
        }
    }
};

bool extract_mrenclave(const std::vector<uint8_t> &quote, std::string *mrenclave_hex);
bool create_app_enclave_report(sgx_enclave_id_t eid,
                               const sgx_target_info_t *target_info,
                               sgx_report_t *report);

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

bool parse_u32(const char *text, uint32_t *value)
{
    if (text == NULL || value == NULL || *text == '\0') {
        return false;
    }
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if (end == NULL || *end != '\0' || parsed == 0UL || parsed > UINT32_MAX) {
        return false;
    }
    *value = static_cast<uint32_t>(parsed);
    return true;
}

std::string enclave_path_for_party(uint32_t party_id)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "./libenclave%u.so", party_id);
    return std::string(filename);
}

std::string bytes_to_hex(const uint8_t *data, size_t size)
{
    static const char *kHex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0f]);
        out.push_back(kHex[data[i] & 0x0f]);
    }
    return out;
}

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

std::string join_path(const std::string &dir, const std::string &name)
{
    if (!dir.empty() && dir.back() == '/') {
        return dir + name;
    }
    return dir + "/" + name;
}

std::string quote_path(const options_t &options, uint32_t party_id)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.quote", party_id);
    return join_path(options.quote_dir, filename);
}

std::string result_path(const options_t &options)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.json", options.party_id);
    return join_path(options.result_dir, filename);
}

std::string report_path(const options_t &options)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.report", options.party_id);
    return join_path(options.result_dir, filename);
}

std::string target_info_path(const options_t &options)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.qe_target_info.bin", options.party_id);
    return join_path(options.result_dir, filename);
}

std::string warmup_target_info_path(const options_t &options)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.warmup.qe_target_info.bin", options.party_id);
    return join_path(options.result_dir, filename);
}

std::string warmup_report_path(const options_t &options)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.warmup.report", options.party_id);
    return join_path(options.result_dir, filename);
}

std::string warmup_quote_path(const options_t &options)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "party_%u.warmup.quote", options.party_id);
    return join_path(options.result_dir, filename);
}

std::string verify_path(const options_t &options, uint32_t party_id)
{
    char filename[64];
    snprintf(filename, sizeof(filename), "verifier_%u_party_%u.verify.json", options.party_id, party_id);
    return join_path(options.result_dir, filename);
}

bool ensure_directory(const std::string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    if (errno != ENOENT) {
        return false;
    }
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
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

bool file_exists(const std::string &path)
{
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string shell_quote(const std::string &value)
{
    std::string quoted = "'";
    for (size_t idx = 0; idx < value.size(); ++idx) {
        if (value[idx] == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(value[idx]);
        }
    }
    quoted += "'";
    return quoted;
}

bool parse_verify_json(const std::vector<uint8_t> &payload, std::string *mrenclave_hex)
{
    const std::string text(payload.begin(), payload.end());
    if (text.find("\"verified\": true") == std::string::npos) {
        return false;
    }
    const std::string key = "\"mrenclave\": \"";
    const size_t key_pos = text.find(key);
    if (key_pos == std::string::npos) {
        return false;
    }
    const size_t value_start = key_pos + key.size();
    const size_t value_end = text.find('"', value_start);
    if (value_end == std::string::npos) {
        return false;
    }
    *mrenclave_hex = text.substr(value_start, value_end - value_start);
    return true;
}

double parse_response_ms(const std::string &response, const char *key)
{
    const std::string prefix = std::string(key) + "=";
    const size_t key_pos = response.find(prefix);
    if (key_pos == std::string::npos) {
        return 0.0;
    }
    const char *value_start = response.c_str() + key_pos + prefix.size();
    char *value_end = NULL;
    const double value = strtod(value_start, &value_end);
    return value_end == value_start ? 0.0 : value;
}

bool generate_local_quote_with_helper(sgx_enclave_id_t eid,
                                      const options_t &options,
                                      helper_session_t *helper,
                                      std::vector<uint8_t> *quote,
                                      std::string *mrenclave_hex,
                                      timing_summary_t *timings)
{
    const uint64_t local_quote_start_ns = monotonic_now_ns();
    const std::string local_target_info_path = target_info_path(options);
    const uint64_t target_info_start_ns = monotonic_now_ns();
    if (!helper->run({"target-info", local_target_info_path})) {
        fprintf(stderr, "quote_helper target-info failed\n");
        return false;
    }
    timings->target_info_ms = elapsed_ms(target_info_start_ns, monotonic_now_ns());

    std::vector<uint8_t> target_info_bytes;
    if (!read_file(local_target_info_path, &target_info_bytes) || target_info_bytes.size() != sizeof(sgx_target_info_t)) {
        fprintf(stderr, "failed to read target info from helper\n");
        return false;
    }

    const sgx_target_info_t *target_info = reinterpret_cast<const sgx_target_info_t *>(target_info_bytes.data());
    sgx_report_t report = {0};
    const uint64_t create_report_start_ns = monotonic_now_ns();
    if (!create_app_enclave_report(eid, target_info, &report)) {
        return false;
    }
    timings->create_report_ms = elapsed_ms(create_report_start_ns, monotonic_now_ns());

    const std::string local_report_path = report_path(options);
    if (!write_atomic_file(local_report_path, reinterpret_cast<const uint8_t *>(&report), sizeof(report))) {
        fprintf(stderr, "failed to write local report file\n");
        return false;
    }

    const std::string local_quote_path = quote_path(options, options.party_id);
    const uint64_t quote_generation_start_ns = monotonic_now_ns();
    std::string quote_response;
    if (!helper->run({"quote", local_report_path, local_quote_path}, &quote_response)) {
        fprintf(stderr, "quote_helper quote failed\n");
        return false;
    }
    timings->quote_generation_ms = elapsed_ms(quote_generation_start_ns, monotonic_now_ns());
    timings->quote_read_report_ms = parse_response_ms(quote_response, "read_report_ms");
    timings->quote_qe_target_info_ms = parse_response_ms(quote_response, "qe_target_info_ms");
    timings->quote_size_ms = parse_response_ms(quote_response, "quote_size_ms");
    timings->quote_get_quote_ms = parse_response_ms(quote_response, "get_quote_ms");
    timings->quote_write_quote_ms = parse_response_ms(quote_response, "write_quote_ms");

    if (!read_file(local_quote_path, quote) || !extract_mrenclave(*quote, mrenclave_hex)) {
        fprintf(stderr, "failed to parse local quote\n");
        return false;
    }
    timings->local_quote_total_ms = elapsed_ms(local_quote_start_ns, monotonic_now_ns());
    return true;
}

bool warmup_quote_with_helper(sgx_enclave_id_t eid, const options_t &options, helper_session_t *helper)
{
    const std::string local_target_info_path = warmup_target_info_path(options);
    if (!helper->run({"target-info", local_target_info_path})) {
        fprintf(stderr, "quote_helper warmup target-info failed\n");
        return false;
    }

    std::vector<uint8_t> target_info_bytes;
    if (!read_file(local_target_info_path, &target_info_bytes) || target_info_bytes.size() != sizeof(sgx_target_info_t)) {
        fprintf(stderr, "failed to read warmup target info from helper\n");
        return false;
    }

    const sgx_target_info_t *target_info = reinterpret_cast<const sgx_target_info_t *>(target_info_bytes.data());
    sgx_report_t report = {0};
    if (!create_app_enclave_report(eid, target_info, &report)) {
        return false;
    }

    const std::string local_report_path = warmup_report_path(options);
    if (!write_atomic_file(local_report_path, reinterpret_cast<const uint8_t *>(&report), sizeof(report))) {
        fprintf(stderr, "failed to write warmup report file\n");
        return false;
    }

    std::string ignored_response;
    if (!helper->run({"quote", local_report_path, warmup_quote_path(options)}, &ignored_response)) {
        fprintf(stderr, "quote_helper warmup quote failed\n");
        return false;
    }
    return true;
}

bool verify_quote_with_helper(const options_t &options,
                              helper_session_t *helper,
                              uint32_t party_id,
                              std::string *mrenclave_hex,
                              peer_timing_t *peer_timing)
{
    const std::string peer_quote_path = quote_path(options, party_id);
    const std::string peer_verify_path = verify_path(options, party_id);
    std::string verify_response;
    if (!helper->run({"verify", peer_quote_path, options.fmspc, options.pck_ca, peer_verify_path}, &verify_response)) {
        fprintf(stderr, "quote_helper verify failed for party %u\n", party_id);
        return false;
    }
    peer_timing->verify_read_quote_ms = parse_response_ms(verify_response, "read_quote_ms");
    peer_timing->verify_parse_quote_ms = parse_response_ms(verify_response, "parse_quote_ms");
    peer_timing->verify_collateral_ms = parse_response_ms(verify_response, "collateral_ms");
    peer_timing->verify_qv_verify_ms = parse_response_ms(verify_response, "qv_verify_ms");
    peer_timing->verify_write_json_ms = parse_response_ms(verify_response, "write_verify_ms");

    std::vector<uint8_t> verify_payload;
    if (!read_file(peer_verify_path, &verify_payload) || !parse_verify_json(verify_payload, mrenclave_hex)) {
        fprintf(stderr, "failed to parse helper verify output for party %u\n", party_id);
        return false;
    }
    return true;
}

bool wait_for_all_quotes(const options_t &options)
{
    const uint64_t deadline_ns = monotonic_now_ns() + static_cast<uint64_t>(options.timeout_sec) * 1000000000ULL;
    while (monotonic_now_ns() < deadline_ns) {
        bool all_ready = true;
        for (uint32_t party = 1; party <= options.parties; ++party) {
            if (!file_exists(quote_path(options, party))) {
                all_ready = false;
                break;
            }
        }
        if (all_ready) {
            return true;
        }
        usleep(10000);
    }
    return false;
}

bool exchange_quotes_with_fabric(const options_t &options)
{
    if (options.fabric_address.empty()) {
        fprintf(stderr, "fabric address is required\n");
        return false;
    }

    const std::string local_quote_path = quote_path(options, options.party_id);
    std::ostringstream command;
    command << "python3 "
            << shell_quote(options.fabric_helper_path)
            << " --address " << shell_quote(options.fabric_address)
            << " --party-id " << options.party_id
            << " --parties " << options.parties
            << " --quote-dir " << shell_quote(options.quote_dir)
            << " --local-quote " << shell_quote(local_quote_path)
            << " --proto-dir " << shell_quote(options.fabric_proto_dir)
            << " --run-id " << shell_quote(options.fabric_run_id)
            << " --poll-interval " << shell_quote(options.fabric_poll_interval)
            << " --timeout " << options.timeout_sec;

    const int ret = system(command.str().c_str());
    if (ret != 0) {
        fprintf(stderr, "fabric quote helper failed: command=%s ret=%d\n", command.str().c_str(), ret);
        return false;
    }
    return true;
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

bool create_app_enclave_report(sgx_enclave_id_t eid,
                               const sgx_target_info_t *target_info,
                               sgx_report_t *report)
{
    uint32_t retval = 1;
    const sgx_status_t ret = enclave_create_report(eid, &retval, target_info, report);
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS) {
        fprintf(stderr, "enclave_create_report failed: sgx=0x%x retval=0x%x\n", ret, retval);
        return false;
    }
    return true;
}

bool enclave_expected_set_contains(sgx_enclave_id_t eid, const std::string &mrenclave_hex)
{
    std::vector<uint8_t> mr_bytes;
    if (!hex_to_bytes(mrenclave_hex, &mr_bytes) || mr_bytes.size() != 32U) {
        fprintf(stderr, "invalid peer mrenclave for enclave-side check\n");
        return false;
    }

    uint32_t retval = 1;
    uint32_t is_match = 0;
    const sgx_status_t sgx_ret =
        enclave_check_derived_measurement(eid, &retval, mr_bytes.data(), &is_match);
    if (sgx_ret != SGX_SUCCESS || retval != 0U) {
        fprintf(stderr, "enclave_check_derived_measurement failed: sgx=0x%x retval=%u\n", sgx_ret, retval);
        return false;
    }
    return is_match == 1U;
}

bool parse_options(int argc, char *argv[], options_t *options)
{
    static const struct option kLongOptions[] = {
        {"party-id", required_argument, NULL, 'i'},
        {"parties", required_argument, NULL, 'p'},
        {"quote-dir", required_argument, NULL, 'q'},
        {"result-dir", required_argument, NULL, 'r'},
        {"timeout-sec", required_argument, NULL, 't'},
        {"fmspc", required_argument, NULL, 'f'},
        {"pck-ca", required_argument, NULL, 'c'},
        {"helper", required_argument, NULL, 'h'},
        {"fabric-address", required_argument, NULL, 'a'},
        {"fabric-helper", required_argument, NULL, 'F'},
        {"fabric-proto-dir", required_argument, NULL, 'P'},
        {"fabric-run-id", required_argument, NULL, 'R'},
        {"fabric-poll-interval", required_argument, NULL, 'I'},
        {NULL, 0, NULL, 0},
    };

    int opt = 0;
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "i:p:q:r:t:f:c:h:a:F:P:R:I:", kLongOptions, NULL)) != -1) {
        switch (opt) {
        case 'i':
            if (!parse_u32(optarg, &options->party_id)) {
                return false;
            }
            break;
        case 'p':
            if (!parse_u32(optarg, &options->parties)) {
                return false;
            }
            break;
        case 'q':
            options->quote_dir = optarg;
            break;
        case 'r':
            options->result_dir = optarg;
            break;
        case 't':
            if (!parse_u32(optarg, &options->timeout_sec)) {
                return false;
            }
            break;
        case 'f':
            options->fmspc = optarg;
            break;
        case 'c':
            options->pck_ca = optarg;
            break;
        case 'h':
            options->helper_path = optarg;
            break;
        case 'a':
            options->fabric_address = optarg;
            break;
        case 'F':
            options->fabric_helper_path = optarg;
            break;
        case 'P':
            options->fabric_proto_dir = optarg;
            break;
        case 'R':
            options->fabric_run_id = optarg;
            break;
        case 'I':
            options->fabric_poll_interval = optarg;
            break;
        default:
            return false;
        }
    }

    if (options->party_id == 0 || options->parties == 0 || options->party_id > options->parties) {
        return false;
    }
    if (options->quote_dir.empty() || options->result_dir.empty() || options->fmspc.size() != 12U) {
        return false;
    }
    if (options->fabric_address.empty()) {
        return false;
    }
    const char *warmup_quote = getenv("WARMUP_QUOTE");
    options->warmup_quote = warmup_quote != NULL && strcmp(warmup_quote, "1") == 0;
    return true;
}

void print_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s --party-id N --parties N --quote-dir DIR --result-dir DIR --fmspc HEX12 --fabric-address HOST:PORT [--pck-ca platform|processor] [--timeout-sec SEC] [--helper PATH] [--fabric-helper PATH] [--fabric-proto-dir DIR] [--fabric-run-id ID] [--fabric-poll-interval SEC]\n",
            program);
}

std::string build_result_json(const options_t &options,
                              uint64_t auth_start_ns,
                              uint64_t auth_end_ns,
                              const verify_summary_t &summary,
                              const timing_summary_t &timings,
                              const char *status,
                              const char *error_text)
{
    const uint64_t auth_duration_us = auth_end_ns > auth_start_ns ? (auth_end_ns - auth_start_ns) / 1000ULL : 0ULL;
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out.precision(3);
    out << "{\n"
        << "  \"party_id\": " << options.party_id << ",\n"
        << "  \"parties\": " << options.parties << ",\n"
        << "  \"auth_start_ns\": " << auth_start_ns << ",\n"
        << "  \"auth_end_ns\": " << auth_end_ns << ",\n"
        << "  \"auth_duration_us\": " << auth_duration_us << ",\n"
        << "  \"auth_duration_ms\": " << elapsed_ms(auth_start_ns, auth_end_ns) << ",\n"
        << "  \"verified_quotes\": " << summary.verified_quotes << ",\n"
        << "  \"identity_matches\": " << summary.identity_matches << ",\n"
        << "  \"local_mrenclave\": \"" << summary.local_mrenclave_hex << "\",\n"
        << "  \"timing_ms\": {\n"
        << "    \"warmup_quote\": " << timings.warmup_quote_ms << ",\n"
        << "    \"target_info\": " << timings.target_info_ms << ",\n"
        << "    \"create_report\": " << timings.create_report_ms << ",\n"
        << "    \"quote_generation\": " << timings.quote_generation_ms << ",\n"
        << "    \"quote_read_report\": " << timings.quote_read_report_ms << ",\n"
        << "    \"quote_qe_target_info\": " << timings.quote_qe_target_info_ms << ",\n"
        << "    \"quote_size\": " << timings.quote_size_ms << ",\n"
        << "    \"quote_get_quote\": " << timings.quote_get_quote_ms << ",\n"
        << "    \"quote_write_quote\": " << timings.quote_write_quote_ms << ",\n"
        << "    \"local_quote_total\": " << timings.local_quote_total_ms << ",\n"
        << "    \"wait_all_quotes\": " << timings.wait_all_quotes_ms << ",\n"
        << "    \"quote_verification_total\": " << timings.quote_verification_total_ms << ",\n"
        << "    \"identity_check_total\": " << timings.identity_check_total_ms << "\n"
        << "  },\n"
        << "  \"peer_timings\": [\n";
    for (size_t idx = 0; idx < timings.peer_timings.size(); ++idx) {
        const peer_timing_t &peer = timings.peer_timings[idx];
        out << "    {"
            << "\"party_id\": " << peer.party_id << ", "
            << "\"quote_verify_ms\": " << peer.quote_verify_ms << ", "
            << "\"verify_read_quote_ms\": " << peer.verify_read_quote_ms << ", "
            << "\"verify_parse_quote_ms\": " << peer.verify_parse_quote_ms << ", "
            << "\"verify_collateral_ms\": " << peer.verify_collateral_ms << ", "
            << "\"verify_qv_verify_ms\": " << peer.verify_qv_verify_ms << ", "
            << "\"verify_write_json_ms\": " << peer.verify_write_json_ms << ", "
            << "\"identity_check_ms\": " << peer.identity_check_ms << ", "
            << "\"quote_verified\": " << (peer.quote_verified ? "true" : "false") << ", "
            << "\"identity_matched\": " << (peer.identity_matched ? "true" : "false")
            << "}";
        if (idx + 1U != timings.peer_timings.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "  ],\n"
        << "  \"status\": \"" << status << "\",\n"
        << "  \"error\": \"" << error_text << "\"\n"
        << "}\n";
    return out.str();
}

int run_party(const options_t &options)
{
    if (!ensure_directory(options.quote_dir) || !ensure_directory(options.result_dir)) {
        fprintf(stderr, "failed to ensure quote/result directories\n");
        return EXIT_FAILURE;
    }

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t launch_token = {0};
    int launch_token_updated = 0;
    const std::string enclave_path = enclave_path_for_party(options.party_id);
    sgx_status_t sgx_ret = sgx_create_enclave(
        enclave_path.c_str(),
        SGX_DEBUG_FLAG,
        &launch_token,
        &launch_token_updated,
        &eid,
        NULL);
    if (sgx_ret != SGX_SUCCESS) {
        fprintf(stderr, "sgx_create_enclave failed: 0x%x\n", sgx_ret);
        return EXIT_FAILURE;
    }

    helper_session_t helper;
    if (!helper.start(options.helper_path)) {
        fprintf(stderr, "failed to start quote_helper server\n");
        sgx_destroy_enclave(eid);
        return EXIT_FAILURE;
    }

    verify_summary_t summary;
    timing_summary_t timings;
    if (options.warmup_quote) {
        const uint64_t warmup_start_ns = monotonic_now_ns();
        if (!warmup_quote_with_helper(eid, options, &helper)) {
            helper.stop();
            sgx_destroy_enclave(eid);
            return EXIT_FAILURE;
        }
        timings.warmup_quote_ms = elapsed_ms(warmup_start_ns, monotonic_now_ns());
    }

    const uint64_t auth_start_ns = monotonic_now_ns();
    uint64_t auth_end_ns = auth_start_ns;
    std::string error_text;

    std::vector<uint8_t> local_quote;
    if (!generate_local_quote_with_helper(eid, options, &helper, &local_quote, &summary.local_mrenclave_hex, &timings)) {
        error_text = "generate_local_quote_failed";
        goto done;
    }
    {
        const uint64_t exchange_start_ns = monotonic_now_ns();
        if (!exchange_quotes_with_fabric(options)) {
            timings.wait_all_quotes_ms = elapsed_ms(exchange_start_ns, monotonic_now_ns());
            error_text = "fabric_quote_exchange_failed";
            goto done;
        }
        timings.wait_all_quotes_ms = elapsed_ms(exchange_start_ns, monotonic_now_ns());
    }

    for (uint32_t party = 1; party <= options.parties; ++party) {
        std::string peer_mrenclave;
        peer_timing_t peer_timing;
        peer_timing.party_id = party;
        const uint64_t verify_start_ns = monotonic_now_ns();
        if (!verify_quote_with_helper(options, &helper, party, &peer_mrenclave, &peer_timing)) {
            peer_timing.quote_verify_ms = elapsed_ms(verify_start_ns, monotonic_now_ns());
            timings.peer_timings.push_back(peer_timing);
            timings.quote_verification_total_ms += peer_timing.quote_verify_ms;
            error_text = "verify_quote_failed";
            goto done;
        }
        peer_timing.quote_verify_ms = elapsed_ms(verify_start_ns, monotonic_now_ns());
        peer_timing.quote_verified = true;
        timings.quote_verification_total_ms += peer_timing.quote_verify_ms;
        ++summary.verified_quotes;

        const uint64_t identity_start_ns = monotonic_now_ns();
        if (enclave_expected_set_contains(eid, peer_mrenclave)) {
            peer_timing.identity_check_ms = elapsed_ms(identity_start_ns, monotonic_now_ns());
            peer_timing.identity_matched = true;
            timings.identity_check_total_ms += peer_timing.identity_check_ms;
            timings.peer_timings.push_back(peer_timing);
            ++summary.identity_matches;
        } else {
            peer_timing.identity_check_ms = elapsed_ms(identity_start_ns, monotonic_now_ns());
            timings.identity_check_total_ms += peer_timing.identity_check_ms;
            timings.peer_timings.push_back(peer_timing);
            error_text = "mage_identity_mismatch";
            goto done;
        }
    }

done:
    auth_end_ns = monotonic_now_ns();
    const char *status =
        (error_text.empty() && summary.verified_quotes == options.parties && summary.identity_matches == options.parties)
            ? "ok"
            : "error";
    if (error_text.empty() && strcmp(status, "ok") != 0) {
        error_text = "incomplete_verification";
    }
    const std::string result_payload = build_result_json(
        options, auth_start_ns, auth_end_ns, summary, timings, status, error_text.empty() ? "" : error_text.c_str());
    if (!write_atomic_text(result_path(options), result_payload)) {
        fprintf(stderr, "failed to write result json\n");
    }

    helper.stop();
    sgx_destroy_enclave(eid);
    return strcmp(status, "ok") == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

}  // namespace

int main(int argc, char *argv[])
{
    options_t options;
    if (!parse_options(argc, argv, &options)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    return run_party(options);
}
