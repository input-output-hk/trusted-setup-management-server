#include <iostream>
#include <stdarg.h>
#include <vector>
// Uses nlohmann-json instead of PicoJSON
// Needs to be specified BEFORE jwt-cpp/jwt.h
// to be taken into account.
#include <jwt-cpp/traits/nlohmann-json/defaults.h> 
#include <jwt-cpp/jwt.h>
#include <AttestationClient.h>
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <algorithm>
#include <thread>
#include <boost/algorithm/string.hpp>
#include "Logger.h"
#include <iostream>
#include <fstream>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <nlohmann/json.hpp>

// default guest attestation url
// The VM is hosted on East US 2
// matching with the default URL.
std::string default_attestation_url = "https://sharedeus2.eus2.attest.azure.net";

// Direct conversion of the C# method to C++
// from the original code snippet
// https://github.com/Azure-Samples/microsoft-azure-attestation/blob/aa9fbb2d8869c020c633f3895f43525aaf60bf59/maa.jwt.verifier.dotnet/Utilities.cs#L38C46-L38C83
std::map<std::string, X509*> load_self_signed_certs(const nlohmann::json& jwks)
{
    std::map<std::string, X509*> out;

    for (auto& key : jwks["keys"])
    {
        std::string kid = key.value("kid", "");
        for (auto& x5c : key["x5c"])
        {
            std::string der_b64 = x5c.get<std::string>();
            std::string der = jwt::base::decode<jwt::alphabet::base64>(der_b64);

            const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
            X509* cert = d2i_X509(nullptr, &p, der.size());
            if (!cert) continue;

            // self-signed check: subject == issuer DN
            if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0)
                out.emplace(kid, cert);
            else
                X509_free(cert);
        }
    }
    if (out.empty()) throw std::runtime_error("no self-signed x5c certs");
    return out;
}

// Computes the SHA256 hash of a file and returns it as a 32-byte array.
// Used to hash all executable files used in the ceremony & attestation process.
std::array<unsigned char, SHA256_DIGEST_LENGTH> compute_file_sha256(const std::string& path) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        fprintf(stderr, "Error: could not open file %s\n", path.c_str());
        return hash;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_MD_CTX_new failed\n");
        return hash;
    }

    const EVP_MD* md = EVP_sha256();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        fprintf(stderr, "Error: EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    std::array<char, 4096> buffer;
    while (file.read(buffer.data(), buffer.size()) || file.gcount()) {
        if (EVP_DigestUpdate(ctx, buffer.data(), file.gcount()) != 1) {
            fprintf(stderr, "Error: EVP_DigestUpdate failed\n");
            EVP_MD_CTX_free(ctx);
            return hash;
        }
    }

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1 || len != hash.size()) {
        fprintf(stderr, "Error: EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return hash;
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string jwk_x5c_to_pem(const nlohmann::json& jwk)
{
    if (!jwk.contains("x5c") || jwk["x5c"].empty())
        throw std::runtime_error("JWK has no x5c certificate");

    std::string der_b64 = jwk["x5c"][0].get<std::string>();
    std::string der = jwt::base::decode<jwt::alphabet::base64>(der_b64);

    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    X509* cert = d2i_X509(nullptr, &p, der.size());
    if (!cert) throw std::runtime_error("X509 decode failed");

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    std::string pem(mem->data, mem->length);

    BIO_free(bio);
    X509_free(cert);
    return pem;
}

std::string trimSlash(std::string s)
{
    if (!s.empty() && s.back() == '/') s.pop_back();
    return s;
};

std::string http_get(const std::string& url)
{
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);

    auto rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK)
        throw std::runtime_error("HTTP GET failed: " + std::string(curl_easy_strerror(rc)));
    return body;
}

// Adapted directly from this example:
// https://github.com/Azure-Samples/microsoft-azure-attestation/blob/aa9fbb2d8869c020c633f3895f43525aaf60bf59/maa.jwt.verifier.dotnet/Program.cs#L94
bool ValidateToken(const jwt::decoded_jwt<jwt::traits::nlohmann_json>& decoded, std::string& expectedIssuer, bool validateLifetime)
{
    jwt::traits::nlohmann_json::object_type payload = decoded.get_payload_json();

    // URL where you can pull the signing certificates
    auto header = decoded.get_header_json();
    std::string jku = header["jku"].get<std::string>();
    std::string kid = header["kid"].get<std::string>();
    printf("Cert URL header: %s\n", jku.c_str());
    printf("Key ID header: %s\n", kid.c_str());

    // Calling JKU / Azure certs endpoint to key the keys
    nlohmann::json jwks_json = nlohmann::json::parse(http_get(jku));
    
    auto it = std::find_if(jwks_json["keys"].begin(), jwks_json["keys"].end(),
                        [&](const auto& k){ return k["kid"] == kid; });
    if (it == jwks_json["keys"].end()) {
        fprintf(stderr, "kid %s not present under %s\n", kid.c_str(), jku.c_str());
        return false;
    }
    printf("Using platform leaf kid=%s for JWT verification\n", kid.c_str());
    std::string pem = jwk_x5c_to_pem(*it);

    if (pem.empty()) {
        fprintf(stderr, "Error: PEM conversion failed for JWK with key ID %s\n", kid.c_str());
        return false;
    }

    // The issuer in the token doesn't end up with /
    // so we need to trim it, in order to pass the validation, in case an issuer was specified with a /.
    expectedIssuer = trimSlash(expectedIssuer);

    // As we only verify the token, we can specify the public key and leave the rest of the parameters empty.
    // jwt-cpp does the heavy lifting here regarding the verification itself
    // If validateLifetime is true, we will use the default clock, otherwise we will give a 100 years skew.
    // This allows us to skip the lifetime verification.

    // Note: Audience verification is skipped here, as the JWT does not have the field `aud`
    // Algorithm::rs256 is used as the JWT is signed using RS256
    auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256(pem, "", "", "")).with_issuer(expectedIssuer);

    if (!validateLifetime) {
        // disable all time checks by giving 100 years skew
        verifier = verifier.expires_at_leeway(3153600000);
        printf("Warning: Lifetime verification has been disabled\n");
    }

    try {
        printf("Verifying the JWT...\n");
        verifier.verify(decoded);
        return true;
    } catch (const std::exception& e) {
        fprintf(stderr, "Error: Exception occured when verifying the JWT. Details - %s\n", e.what());
        return false;
    }
}

// Encode the hash blob to base64
// I cannot use the jwt-cpp library here, as it does expect a string as input,
// and the hash blob is a vector of bytes...
// OpenSSL encoding methods will be used here.
// Leverage OpenSSL's BIO functions for this purpose.
std::string base64_encode(const unsigned char* input, size_t length) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string result(buffer_ptr->data, buffer_ptr->length);

    BIO_free_all(bio);
    return result;
}

// Decode the base64 encoded string to a vector of bytes
// Unfortunately necessary as jwt-cpp does not support decoding base64 to a vector of bytes directly.
// Leverage OpenSSL's BIO functions for this purpose.
std::vector<std::uint8_t> base64_decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines

    std::vector<std::uint8_t> output(input.size() * 3 / 4); // Base64 expands 3:4
    int decoded_size = BIO_read(bio, output.data(), static_cast<int>(output.size()));
    output.resize(decoded_size > 0 ? decoded_size : 0);

    BIO_free_all(bio);
    return output;
}

std::string to_hex(const std::uint8_t* p, std::size_t len)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(p[i]);
    return oss.str();
}

void check_policy(jwt::traits::nlohmann_json::object_type& raw, nlohmann::json& policy)
{
    nlohmann::json payload = raw;

    // Get the hashes blob (srs & executable)
    std::string hash_blob_b64 = payload["x-ms-runtime"]["client-payload"]["hash_srs_blob"].get<std::string>();
    std::string blob_exec_b64 = payload["x-ms-runtime"]["client-payload"]["blob_exec_hashes"].get<std::string>();

    // Decode base64 to binary
    // jwt-cpp does not support decoding base64 to a vector of bytes directly,
    // so we use our own base64_decode function.
    // The decode has to be done twice too, due to MAA encoding the hash blobs in base64,
    // while we already encoded them in base64 before sending them to MAA...
    std::vector<std::uint8_t> hash_blob = base64_decode(jwt::base::decode<jwt::alphabet::base64>(hash_blob_b64));
    std::vector<std::uint8_t> blob_exec = base64_decode(jwt::base::decode<jwt::alphabet::base64>(blob_exec_b64));

    std::array<std::uint8_t, 32> sha_srs{}, sha_proof{}, sha_srs_utils{}, sha_srs_srv{};

    // Extract the SRS hash and proof hash from the hash blob
    std::memcpy(sha_srs.data(), hash_blob.data(), 32);
    std::memcpy(sha_proof.data(), hash_blob.data() + 32, 32);

    std::string srs_hash = to_hex(sha_srs.data(), sha_srs.size());
    std::string proof_hash = to_hex(sha_proof.data(), sha_proof.size());

    // Extract the hashes of the executables from the blob
    std::memcpy(sha_srs_utils.data(), blob_exec.data(), 32);
    std::memcpy(sha_srs_srv.data(), blob_exec.data() + 32, 32);

    std::string srs_utils_hash = to_hex(sha_srs_utils.data(), sha_srs_utils.size());
    std::string srs_srv_hash = to_hex(sha_srs_srv.data(), sha_srs_srv.size());

    using pair = std::pair<const char*, const char*>;
    // Map of fields we want to check.
    // Made this way in order to be personalized easily.
    static const std::vector<pair> map = {
        {"attestation-type",            "/x-ms-isolation-tee/x-ms-attestation-type"},
        {"compliance-status",           "/x-ms-isolation-tee/x-ms-compliance-status"},
        {"vm_id",                       "/x-ms-azurevm-vmid"},
        {"secureboot",                  "/secureboot"},
        {"kerneldebug-enabled",         "/x-ms-azurevm-kerneldebug-enabled"},
        {"imageId",                     "/x-ms-isolation-tee/x-ms-sevsnpvm-imageId"},
        {"microcode-svn",               "/x-ms-isolation-tee/x-ms-sevsnpvm-microcode-svn"},
        {"snpfw-svn",                   "/x-ms-isolation-tee/x-ms-sevsnpvm-snpfw-svn"},
        {"launch_measurement",          "/x-ms-isolation-tee/x-ms-sevsnpvm-launchmeasurement"},
        {"srs_hash",                    ""},
        {"proof_hash",                  ""},
        {"srs_utils_hash",              ""},
        {"srs_srv_hash",                ""},
    };

    auto check_field = [&](const char* key, const std::string& expected, const std::string& actual) {
        if (expected == actual) {
            printf("Policy check passed for %s: %s\n", key, actual.c_str());
        } else {
            throw std::runtime_error("policy mismatch @ " + std::string(key) +
                                    "\n  expected: " + expected +
                                    "\n  got     : " + actual);
        }
    };

    for (auto [key, path] : map) {
        if (key == "srs_hash") {
            check_field(key, policy[key].get<std::string>(), srs_hash);
        } else if (key == "proof_hash") {
            check_field(key, policy[key].get<std::string>(), proof_hash);
        } else if (key == "srs_utils_hash") {
            check_field(key, policy[key].get<std::string>(), srs_utils_hash);
        } else if (key == "srs_srv_hash") {
            check_field(key, policy[key].get<std::string>(), srs_srv_hash);
        } else {
            nlohmann::json::json_pointer ptr{std::string(path)};
            if (!payload.contains(ptr))
                throw std::runtime_error("attestation missing " + std::string(path));
            if (payload[ptr] == policy[key])
                printf("Policy check passed for %s: %s\n", key, payload[ptr].dump().c_str());
            else
                throw std::runtime_error("policy mismatch @ " + std::string(key) +
                                        "\n  expected: " + policy[key].dump() +
                                        "\n  got     : " + payload[ptr].dump());
        }
    }
    printf("Attestation compliant with the policy!\n");
}

void usage(char* programName) {
    printf("Usage: %s -o <output_file> -h <hash_file> | -v <input_file> -p <policy_file>\n", programName);
}

int main(int argc, char* argv[]) {
    std::string attestation_url;
    std::string nonce = "midnight-srs"; // Hardcoded nonce
    std::string output_file;
    std::string input_file;
    std::string hash_file;
    std::string policy_file;
    bool validate_lifetime = false;

    int opt;
    while ((opt = getopt(argc, argv, ":o:v:a:h:t:p:")) != -1) {
        switch (opt) {
        case 'o':
            output_file.assign(optarg);
            break;
        case 'v':
            input_file.assign(optarg);
            break;
        case 'a':
            attestation_url.assign(optarg);
            break;
        case 'h':
            hash_file.assign(optarg);
            break;
        case 't':
            validate_lifetime = true;
            break;
        case 'p':
            policy_file.assign(optarg);
            break;
        case ':':
            fprintf(stderr, "Option needs a value\n");
            return (1);
        default:
            usage(argv[0]);
            return (1);
        }
    }

    try {
        if (attestation_url.empty()) {
            // use the default attestation url
            attestation_url.assign(default_attestation_url);
        }

        if (!output_file.empty() && !input_file.empty()) {
            fprintf(stderr, "Error: You cannot get and verify an attestation at the same time\n");
            return (1);
        }

        if (output_file.empty() && input_file.empty()) {
            // if no output file is specified, use the default output file
            output_file = "attestation.txt";
        }

        if (policy_file.empty()) {
            policy_file = "policy.json";
        }

        if (!output_file.empty() && hash_file.empty()) {
            fprintf(stderr, "Error: You must specify a hash file when generating an attestation\n");
            exit(1);
        }

        if (!output_file.empty()) {
            AttestationClient* attestation_client = nullptr;
            Logger* log_handle = new Logger();

            // Initialize attestation client
            if (!Initialize(log_handle, &attestation_client)) {
                fprintf(stderr, "Failed to create attestation client object\n");
                Uninitialize();
                return (1);
            }

            // Get hashes from the hash file
            // The size is hardcoded to 64 bytes because we expect 2 hashes only for now.
            std::array<std::uint8_t, 64> srs_hashes{};
            std::ifstream hash(hash_file, std::ios::binary);
            if (!hash) {
                fprintf(stderr, "Error: Could not open hash file %s\n", hash_file.c_str());
                exit(1);
            }

            // Read the hash file into the srs_hashes array
            // The hash blob is a vector of bytes containing the two hashes concatenated together.
            // The first 32 bytes are the SRS hash, and the next 32 bytes are the proof hash.
            hash.read(reinterpret_cast<char*>(srs_hashes.data()), srs_hashes.size());

            // Encode the hash blob to base64
            // There is one issue here, the MAA library will encode this into Base64 too.
            // A double decoding will occur when verifying the attestation.
            // This is beyond stupid, but it is what it is.
            std::string blob_srs_base64 = base64_encode(srs_hashes.data(), srs_hashes.size());

            // Get hashes of all executable files used in the ceremony

            // Get hash of the SRS executable
            std::array<uint8_t, SHA256_DIGEST_LENGTH> srs_utils_hash = compute_file_sha256("./srs_utils");

            // Get hash of the SRS server executable
            std::array<uint8_t, SHA256_DIGEST_LENGTH> srs_srv_hash = compute_file_sha256("./srs-srv");

            // Add everything into a single blob
            // This blob will be signed and added to the attestation
            std::vector<uint8_t> blob_exec_hashes;
            blob_exec_hashes.insert(blob_exec_hashes.end(), srs_utils_hash.begin(), srs_utils_hash.end());
            blob_exec_hashes.insert(blob_exec_hashes.end(), srs_srv_hash.begin(), srs_srv_hash.end());

            std::ofstream outFile("app_hashes.bin", std::ios::binary);
            if (!outFile) {
                fprintf(stderr, "Error: Could not open output file app_hashes.bin\n");
                return 1;
            }
            outFile.write(reinterpret_cast<const char*>(blob_exec_hashes.data()), blob_exec_hashes.size());
            outFile.close();

            // Encode the blob of executable hashes to base64
            // Will be encoded again by the MAA library, unfortunately.
            std::string blob_exec_hashes_base64 = base64_encode(blob_exec_hashes.data(), blob_exec_hashes.size());

            // Print all hashes before performing the attestation
            // Those values should be noted down and used in the policy file.
            std::array<std::uint8_t, 32> sha_srs{}, sha_proof{};

            // Extract the SRS hash and proof hash from the hash blob
            std::memcpy(sha_srs.data(), srs_hashes.data(), 32);
            std::memcpy(sha_proof.data(), srs_hashes.data() + 32, 32);

            std::string srs_hash = to_hex(sha_srs.data(), sha_srs.size());
            std::string proof_hash = to_hex(sha_proof.data(), sha_proof.size());

            printf("SRS hash: %s\n", srs_hash.c_str());
            printf("Proof hash: %s\n", proof_hash.c_str());
            printf("SRS Utils hash: %s\n", to_hex(srs_utils_hash.data(), srs_utils_hash.size()).c_str());
            printf("SRS Server hash: %s\n", to_hex(srs_srv_hash.data(), srs_srv_hash.size()).c_str());

            // Generate the attestation
            // This part is critical as we bind the current attestation with our data.
            // The JWT generated will contains our data and will be signed using Microsoft's key,
            // cryptographically binding the attestation to our data.
            attest::ClientParameters params = {};
            params.attestation_endpoint_url = (unsigned char*)attestation_url.c_str();
            std::string payload = "{\"nonce\":\"" + nonce + "\",\"hash_srs_blob\":\"" + blob_srs_base64 + "\",\"blob_exec_hashes\":\"" + blob_exec_hashes_base64 + "\"}";
            params.client_payload = (unsigned char*) payload.c_str();
            params.version = CLIENT_PARAMS_VERSION; // Version 1
            unsigned char* jwt = nullptr;
            attest::AttestationResult result;
            
            bool is_cvm = false;
            bool attestation_success = true;
            std::string jwt_str;
            // Generate the attestation using MAA.
            // Internally, the HCL report is generated, parsed, 
            // and served under the MAA attestation system.
            if ((result = attestation_client->Attest(params, &jwt)).code_ 
                    != attest::AttestationResult::ErrorCode::SUCCESS) {
                attestation_success = false;
            }
        
            if (attestation_success) {
                jwt_str = reinterpret_cast<char*>(jwt);
                printf("Attestation generated. JWT token: %s\n\n", jwt_str.c_str());
                attestation_client->Free(jwt);
                
                jwt::decoded_jwt<jwt::traits::nlohmann_json> decoded = jwt::decode(jwt_str);
                jwt::traits::nlohmann_json::object_type payload = decoded.get_payload_json();

                try {
                    printf("Decoded JWT payload:\n");
                    for (const auto& [key, value] : payload) {
                        printf("  %s: %s\n", key.c_str(), value.dump().c_str());
                    }
                    printf("\n");
                    printf("Now verifying if the attestation is from a compliant AMD-SEV-SNP CVM.\n");
                    // Initial check to see if we truly are in a AMD-SEV-SNP
                    // environment. This check is mandatory as MAA works with multiple
                    // attestation system, such as SGX, TDX.
                    const nlohmann::json& tee = payload["x-ms-isolation-tee"];
                    std::string attestation_type  = tee["x-ms-attestation-type"];
                    std::string compliance_status = tee["x-ms-compliance-status"];

                    if (boost::iequals(attestation_type,  "sevsnpvm") &&
                        boost::iequals(compliance_status, "azure-compliant-cvm"))
                    {
                        is_cvm = true;
                        printf("The running VM is a compliant AMD-SEV-SNP CVM.\n");
                    }
                }
                catch (...) { }
            }

            if (is_cvm) {
                std::ofstream attestation_file(output_file);
                attestation_file << jwt_str;
                attestation_file.close();
                printf("JWT token written to %s\n", output_file.c_str());
            }
            else {
                fprintf(stderr, "Error: The running VM does not seems to be a compliant AMD-SEV-SNP CVM. The attestation cannot be safely performed\n");
                return (1);
            }

            Uninitialize();
        }
        else if (!input_file.empty()) {
            // Verify the attestation
            std::ifstream attestation_file(input_file);
            if (!attestation_file) {
                fprintf(stderr, "Error: Could not open attestation file %s\n", input_file.c_str());
                exit(1);
            }

            std::string jwt_str((std::istreambuf_iterator<char>(attestation_file)),
                                 std::istreambuf_iterator<char>());
            attestation_file.close();

            printf("JWT token read from %s\n", input_file.c_str());
            printf("Verifying JWT token: %s\n", jwt_str.c_str());

            jwt::decoded_jwt<jwt::traits::nlohmann_json> decoded = jwt::decode(jwt_str);

            // Validate the token
            // The validateTimelife setting is by default false as this is not required in our POC
            // but it can be activated if you want to check the token lifetime with -t.
            bool is_valid = ValidateToken(decoded, attestation_url, validate_lifetime);
            if (is_valid) {
                printf("JWT token is valid.\n");
            } else {
                fprintf(stderr, "Error: JWT token is invalid.\n");
                exit(1);
            }

            // The OID extension (1.3.6.1.4.1.311.105.1000.1) is not used here, as the current report (06/12/2025) embedded everything already in 
            // x-ms-isolation-tee.
            // This seems to math with the following documentation from Microsoft: https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/confidential-computing/guest-attestation-confidential-vms.md#json-web-token
            // An initial attempt was made to extract the data from it, but this extension is missing from all keys. The available extensions are only for SGX.
            // The rest of this CLI will only parse the x-ms-isolation-tee field.

            jwt::traits::nlohmann_json::object_type payload = decoded.get_payload_json();
            std::ifstream policy(policy_file);
            if (!policy) {
                fprintf(stderr, "Error: Could not open policy file %s\n", policy_file.c_str());
                fprintf(stderr, "The attestation cannot be validated fully without a policy file.");
                exit(1);
            }
            std::string policy_str((std::istreambuf_iterator<char>(policy)),
                                std::istreambuf_iterator<char>());
            policy.close();
            // Validate the policy. 
            // Not a lot of field are verified at the moment, but this can always be changed.
            nlohmann::json policy_json = nlohmann::json::parse(policy_str);
            check_policy(payload, policy_json);
            printf("Policy check passed.\n");
            printf("Attestation verified successfully.\n");
        }
    }
    catch (std::exception& e) {
        fprintf(stderr, "Error: Exception occured. Details - %s\n", e.what());
        return (1);
    }
    return (0);
}
