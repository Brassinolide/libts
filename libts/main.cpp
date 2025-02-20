#include <openssl/ts.h>

//理论上，openssl只需要支持ts模块
//所以我参考https://github.com/openssl/openssl/blob/master/INSTALL.md#enable-and-disable-features 移除了一些不必要的功能
//编译后的openssl文件夹仅157MB大（原先有6GB多）
//我对openssl不了解，可能移除错导致程序出错或性能损失，不过目前没有测试出来
//perl Configure VC-WIN64A no-err no-filenames no-shared no-apps no-autoload-config no-tests no-deprecated no-docs no-legacy no-sock no-srp no-srtp no-psk no-ui-console no-quic no-dgram no-http no-ssl no-ssl3 no-tls no-dtls no-engine no-comp no-ec no-ec2m no-dynamic-engine no-ocsp no-cms -d --prefix=G:/build/64

enum class ReturnCode {
    Unknown,
    Verification_OK,
    Verification_FAIL,
    ERR_INVALID_PARAM,
    ERR_CANT_OPEN_FILE,
    ERR_CANT_CREATE_DATA,
};

enum class CA_TYPE {
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
#elif _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #pragma comment(lib,"crypt32.lib")
    #ifndef _WIN64
        #error Unsupported CPU architecture
    #endif
    #define SYSTEM_CA "org.openssl.winstore://"
    #define SYSTEM_CA_TYPE CA_TYPE::CA_STORE

    #ifdef _DEBUG
        #define LIB_EXPORT
        int main() {
            ReturnCode ts_verify_file(const char* data_file, const char* sign_file, CA_TYPE ca_type, const char* ca);

            ReturnCode ret = ts_verify_file("C:\\Users\\ADMIN\\Desktop\\ts.c", "C:\\Users\\ADMIN\\Desktop\\ts.c.tsr", CA_TYPE::CA_SYSTEM, 0);
            
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

#define PARAM_REQUIRED(v) if (v == NULL) {return ReturnCode::ERR_INVALID_PARAM;}
#define PARAM_SHOULD_BETWEEN(v,minv,maxv) if(v < minv || v > maxv){return ReturnCode::ERR_INVALID_PARAM;}

#define IF_NULL(v, err) if (v == NULL) { return_code = err; goto end;}
#define IF_LESS_OR_EQUAL_ZERO(v, err) if (v <= 0) { return_code = err; goto end;}
#define UNREACHABLE_BRANCH(err) return_code = err; goto end;

LIB_EXPORT ReturnCode ts_verify_file(const char* data_file, const char* sign_file, CA_TYPE ca_type, const char* ca) {
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
    BIO* data_bio = NULL; //free in TS_VERIFY_CTX_set0_data
    TS_RESP* response = NULL;
    TS_VERIFY_CTX* verify_ctx = NULL;
    X509_STORE* cert_ctx = NULL; //free in TS_VERIFY_CTX_set0_store
    X509_LOOKUP* cert_lookup = NULL;
    ReturnCode return_code = ReturnCode::Unknown;

    sign_bio = BIO_new_file(sign_file, "rb");
    IF_NULL(sign_bio, ReturnCode::ERR_CANT_OPEN_FILE);

    response = d2i_TS_RESP_bio(sign_bio, NULL);
    IF_NULL(response, ReturnCode::ERR_CANT_OPEN_FILE);

    data_bio = BIO_new_file(data_file, "rb");
    IF_NULL(data_bio, ReturnCode::ERR_CANT_OPEN_FILE);

    //create verify ctx
    verify_ctx = TS_VERIFY_CTX_new();
    IF_NULL(verify_ctx, ReturnCode::ERR_CANT_CREATE_DATA);

    IF_NULL(TS_VERIFY_CTX_set0_data(verify_ctx, data_bio), ReturnCode::ERR_CANT_CREATE_DATA);

    IF_NULL(TS_VERIFY_CTX_add_flags(verify_ctx, TS_VFY_VERSION | TS_VFY_SIGNER | TS_VFY_DATA | TS_VFY_SIGNATURE), ReturnCode::ERR_CANT_CREATE_DATA);
    
    //create cert ctx
    cert_ctx = X509_STORE_new();
    IF_NULL(cert_ctx, ReturnCode::ERR_CANT_CREATE_DATA);

    switch (ca_type) {
    case CA_TYPE::CA_FILE:
        cert_lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
        IF_NULL(cert_lookup, ReturnCode::ERR_CANT_CREATE_DATA);

        IF_LESS_OR_EQUAL_ZERO(X509_LOOKUP_load_file_ex(cert_lookup, ca, X509_FILETYPE_PEM, 0, 0), ReturnCode::ERR_CANT_OPEN_FILE);

        break;
    case CA_TYPE::CA_PATH:
        cert_lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
        IF_NULL(cert_lookup, ReturnCode::ERR_CANT_CREATE_DATA);

        IF_LESS_OR_EQUAL_ZERO(X509_LOOKUP_add_dir(cert_lookup, ca, X509_FILETYPE_PEM), ReturnCode::ERR_CANT_OPEN_FILE);

        break;
    case CA_TYPE::CA_STORE:
        cert_lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_store());
        IF_NULL(cert_lookup, ReturnCode::ERR_CANT_CREATE_DATA);

        IF_LESS_OR_EQUAL_ZERO(X509_LOOKUP_add_store_ex(cert_lookup, ca, 0, 0), ReturnCode::ERR_CANT_OPEN_FILE);

        break;
    default:
        UNREACHABLE_BRANCH(ReturnCode::ERR_INVALID_PARAM);

        break;
    }

    IF_NULL(TS_VERIFY_CTX_set0_store(verify_ctx, cert_ctx), ReturnCode::ERR_CANT_CREATE_DATA);

    //verify it
    if (TS_RESP_verify_response(verify_ctx, response)) {
        return_code = ReturnCode::Verification_OK;
    }
    else {
        return_code = ReturnCode::Verification_FAIL;
    }

end:
    BIO_free_all(sign_bio);
    TS_RESP_free(response);
    TS_VERIFY_CTX_free(verify_ctx);
    return return_code;
}
