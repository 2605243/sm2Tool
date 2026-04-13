#ifndef SM2_ENCRYPT_TOOL_H
#define SM2_ENCRYPT_TOOL_H

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "EncodeTool.h"

class SM2EncryptTool {
public:
    static EVP_PKEY* LoadPrivateKeyFromHEX(const std::string& hex);
    static EVP_PKEY* LoadPublicKeyFromHEX(const std::string& hex);

    // ---------- SM2 加解密 ----------
    // 使用公钥加密
    static bool SM2_Encrypt(EVP_PKEY* pubkey,
                            const std::string& plaintext,
                            std::string& ciphertext);

    // 使用私钥解密
    static bool SM2_Decrypt(EVP_PKEY* privkey,
                            const std::string& ciphertext,
                            std::string& plaintext);

    // ---------- SM2 签名与验签 ----------
    // 使用私钥签名 (消息原文)
    static bool SM2_Sign(EVP_PKEY* privkey,
                         const std::string& message,
                         std::string& signature);

    // 使用公钥验签
    static bool SM2_Verify(EVP_PKEY* pubkey,
                           const std::string& message,
                           const std::string& signature);

    static bool SM2_DER_to_C1C3C2(const std::string& derCipher, std::string& rawCipher);

    static bool SM2_C1C3C2_to_DER(const std::string& rawCipher, std::string& derCipher);

    static bool SM2_DER_to_RAW(const std::string& der, std::string& raw);
    static bool SM2_RAW_to_DER(const std::string& raw, std::string& der);

private:
    // 内部辅助：确保 SM2 密钥在 1.1.1 版本下被正确识别
    static void EnsureSM2Key(EVP_PKEY* pkey);
};

// 内存释放器 (用于 std::unique_ptr)
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
struct BIO_Deleter {
    void operator()(BIO* b) const { if (b) BIO_free(b); }
};
struct EC_KEY_Deleter {
    void operator()(EC_KEY* p) const { if (p) EC_KEY_free(p); }
};
struct EC_POINT_Deleter {
    void operator()(EC_POINT* p) const { if (p) EC_POINT_free(p); }
};
struct BIGNUM_Deleter {
    void operator()(BIGNUM* p) const { if (p) BN_free(p); }
};
struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); }
};

#endif 