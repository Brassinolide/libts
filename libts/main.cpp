#include <openssl/ts.h>
#include <openssl/err.h>

enum class ReturnCode:int {
    UNDEFINED,
    VERIFICATION_OK,
    VERIFICATION_FAIL,
    INVALID_PARAM,
    OPENSSL_ERROR,
};

enum class CA_TYPE:int {
    CA_SYSTEM,
    CA_FILE,
    CA_PATH,
    CA_STORE,
};

#ifndef NULL
    #define NULL 0
#endif

#ifdef __linux__
    #define LIB_EXPORT extern "C" __attribute__((visibility("default")))
    #define SYSTEM_CA "/etc/ssl/certs"
    #define SYSTEM_CA_TYPE CA_TYPE::CA_PATH
    #ifndef __x86_64__
        #error Unsupported CPU architecture
    #endif
    #define TLS_VAR __thread
#elif _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #pragma comment(lib,"crypt32.lib")
    #ifndef _WIN64
        #error Unsupported CPU architecture
    #endif
    #define SYSTEM_CA "org.openssl.winstore://"
    #define SYSTEM_CA_TYPE CA_TYPE::CA_STORE
    #define TLS_VAR __declspec(thread)

    #ifdef _DEBUG
        #define LIB_EXPORT
        int main() {
            ReturnCode ts_verify_file(const char* data_file, const char* sign_file, CA_TYPE ca_type, const char* ca, bool parse_resp);
            const char* ts_get_last_openssl_error();
            time_t resp_get_signing_time();

            ReturnCode ret = ts_verify_file("C:\\Users\\ADMIN\\Desktop\\esc.txt", "C:\\Users\\ADMIN\\Desktop\\esc.txt.tsr", CA_TYPE::CA_SYSTEM, 0, true);
            printf("%s\n", ts_get_last_openssl_error());
            printf("%lld\n", resp_get_signing_time());

        }
    #else
        #define LIB_EXPORT extern "C" __declspec(dllexport)
        BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
            //如果你要静态链接CRT，请移除此代码
            if (fdwReason == DLL_PROCESS_ATTACH) {
                DisableThreadLibraryCalls(hinstDLL);
            }
            return TRUE;
        }
    #endif
#else
    #error Unsupported operating systems
#endif

#define PARAM_REQUIRED(v) if (v == NULL) {return ReturnCode::INVALID_PARAM;}
#define PARAM_SHOULD_BETWEEN(v,minv,maxv) if(v < minv || v > maxv){return ReturnCode::INVALID_PARAM;}

#define OSSL_ERR() return_code = ReturnCode::OPENSSL_ERROR; goto end;
#define OSSL_ERR_IF_NULL(v) if (v == NULL) { return_code = ReturnCode::OPENSSL_ERROR; goto end;}
#define OSSL_ERR_IF_LESS_OR_EQUAL_ZERO(v) if (v <= 0) { return_code = ReturnCode::OPENSSL_ERROR; goto end;}
#define UNREACHABLE_BRANCH() return_code = ReturnCode::UNDEFINED; goto end;

TLS_VAR char openssl_err_msg[2048] = { 0 };
LIB_EXPORT const char* ts_get_last_openssl_error() {
    ERR_error_string_n(ERR_get_error(), openssl_err_msg, sizeof(openssl_err_msg));
    return openssl_err_msg;
}

TLS_VAR bool resp_parsed = false;
TLS_VAR time_t resp_signing_time = 0;
LIB_EXPORT time_t resp_get_signing_time() {
    if (!resp_parsed)return 0;
    return resp_signing_time;
}

LIB_EXPORT ReturnCode ts_verify_file(const char* data_file, const char* sign_file, CA_TYPE ca_type, const char* ca, bool parse_resp) {
    resp_parsed = false;
    
    PARAM_REQUIRED(data_file);
    PARAM_REQUIRED(sign_file);
    PARAM_SHOULD_BETWEEN(ca_type, CA_TYPE::CA_SYSTEM, CA_TYPE::CA_STORE);
    if (ca_type == CA_TYPE::CA_SYSTEM) {
        ca = SYSTEM_CA;
        ca_type = SYSTEM_CA_TYPE;
    }
    else {
        PARAM_REQUIRED(ca);
    }

    BIO* sign_bio = NULL;
    BIO* data_bio = NULL;
    TS_RESP* response = NULL;
    TS_VERIFY_CTX* verify_ctx = NULL;
    X509_STORE* cert_ctx = NULL;
    X509_LOOKUP* cert_lookup = NULL;
    ReturnCode return_code = ReturnCode::UNDEFINED;

    sign_bio = BIO_new_file(sign_file, "rb");
    OSSL_ERR_IF_NULL(sign_bio);

    response = d2i_TS_RESP_bio(sign_bio, NULL);
    OSSL_ERR_IF_NULL(response);

    if (parse_resp) {
        PKCS7* token = NULL;
        TS_TST_INFO* tst_info = NULL;
        const ASN1_GENERALIZEDTIME* signing_time = NULL;
        struct tm _tm = { 0 };

        token = TS_RESP_get_token(response);
        OSSL_ERR_IF_NULL(token);

        tst_info = PKCS7_to_TS_TST_INFO(token);
        OSSL_ERR_IF_NULL(tst_info);

        signing_time = TS_TST_INFO_get_time(tst_info);
        OSSL_ERR_IF_NULL(signing_time);
        
        OSSL_ERR_IF_NULL(ASN1_GENERALIZEDTIME_check(signing_time));
        OSSL_ERR_IF_NULL(ASN1_TIME_to_tm(signing_time, &_tm));

        _tm.tm_isdst = -1;
        resp_signing_time = mktime(&_tm);
        resp_parsed = true;
    }

    data_bio = BIO_new_file(data_file, "rb");
    OSSL_ERR_IF_NULL(data_bio);

    //create verify ctx
    verify_ctx = TS_VERIFY_CTX_new();
    OSSL_ERR_IF_NULL(verify_ctx);

    OSSL_ERR_IF_NULL(TS_VERIFY_CTX_set0_data(verify_ctx, data_bio));

    OSSL_ERR_IF_NULL(TS_VERIFY_CTX_add_flags(verify_ctx, TS_VFY_VERSION | TS_VFY_SIGNER | TS_VFY_DATA | TS_VFY_SIGNATURE));
    
    //create cert ctx
    cert_ctx = X509_STORE_new();
    OSSL_ERR_IF_NULL(cert_ctx);

    switch (ca_type) {
    case CA_TYPE::CA_FILE:
        cert_lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
        OSSL_ERR_IF_NULL(cert_lookup);

        OSSL_ERR_IF_LESS_OR_EQUAL_ZERO(X509_LOOKUP_load_file_ex(cert_lookup, ca, X509_FILETYPE_PEM, 0, 0));

        break;
    case CA_TYPE::CA_PATH:
        cert_lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
        OSSL_ERR_IF_NULL(cert_lookup);

        OSSL_ERR_IF_LESS_OR_EQUAL_ZERO(X509_LOOKUP_add_dir(cert_lookup, ca, X509_FILETYPE_PEM));

        break;
    case CA_TYPE::CA_STORE:
         cert_lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_store());
         OSSL_ERR_IF_NULL(cert_lookup);

         OSSL_ERR_IF_LESS_OR_EQUAL_ZERO(X509_LOOKUP_add_store_ex(cert_lookup, ca, 0, 0));

        break;
    default:
        UNREACHABLE_BRANCH();

        break;
    }

    OSSL_ERR_IF_NULL(TS_VERIFY_CTX_set0_store(verify_ctx, cert_ctx));

    //verify it
    if (TS_RESP_verify_response(verify_ctx, response)) {
        return_code = ReturnCode::VERIFICATION_OK;
    }
    else {
        return_code = ReturnCode::VERIFICATION_FAIL;
    }

end:
    BIO_free_all(sign_bio);
    TS_RESP_free(response);
    TS_VERIFY_CTX_free(verify_ctx);
    return return_code;
}
