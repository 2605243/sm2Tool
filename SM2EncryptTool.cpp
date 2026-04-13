#include "SM2EncryptTool.h"
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

std::string GetOpenSSLError() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

void SM2EncryptTool::EnsureSM2Key(EVP_PKEY* pkey) {
    if (!pkey) return;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    int nid = EVP_PKEY_id(pkey);
    if (nid == EVP_PKEY_EC) {
        EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (ec && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) == NID_sm2) {
            if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) == 1)
            {
                std::cout << "set EVP_PKEY_SM2 success" << std::endl;
            }
            int pkey_type = EVP_PKEY_id(pkey);
            std::cerr << "GetPublicKeyHex: Key type is (" << pkey_type << ")" << std::endl;
        }
    }
#endif
}

EVP_PKEY* SM2EncryptTool::LoadPublicKeyFromHEX(const std::string& hex) {
    std::string pub_bytes = hex_decode(hex);
    if (pub_bytes.size() != 64) {
        return nullptr;
    }

    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec_key(EC_KEY_new_by_curve_name(NID_sm2));
    if (!ec_key) return nullptr;

    const unsigned char* x_data = (unsigned char*)pub_bytes.data();
    const unsigned char* y_data = (unsigned char*)pub_bytes.data() + 32;

    std::unique_ptr<BIGNUM, BIGNUM_Deleter> x(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> y(BN_new());
    if (!x || !y) {
        return nullptr;
    }

    BN_bin2bn(x_data, 32, x.get());
    BN_bin2bn(y_data, 32, y.get());

    const EC_GROUP* group = EC_KEY_get0_group(ec_key.get());
    std::unique_ptr<EC_POINT, EC_POINT_Deleter> point(EC_POINT_new(group));
    if (!point) return nullptr;

    if (!EC_POINT_set_affine_coordinates(group, point.get(), x.get(), y.get(), nullptr)) {
        return nullptr;
    }

    if (EC_KEY_set_public_key(ec_key.get(), point.get()) != 1) {
        return nullptr;
    }

    if (EC_KEY_check_key(ec_key.get()) != 1) {
        return nullptr;
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(EVP_PKEY_new());
    if (!pkey) return nullptr;

    if (EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key.get()) != 1) {
        return nullptr;
    }

    ec_key.release();
    EnsureSM2Key(pkey.get());
    return pkey.release();
}

EVP_PKEY* SM2EncryptTool::LoadPrivateKeyFromHEX(const std::string& hex) {
    std::string priv_bytes = hex_decode(hex);
    if (priv_bytes.size() != 32) return nullptr;

    std::unique_ptr<EC_KEY, EC_KEY_Deleter> ec_key(EC_KEY_new_by_curve_name(NID_sm2));
    if (!ec_key) return nullptr;

    std::unique_ptr<BIGNUM, BIGNUM_Deleter> priv_bn(BN_bin2bn((unsigned char*)priv_bytes.data(), priv_bytes.size(), nullptr));
    if (!priv_bn) return nullptr;

    if (EC_KEY_set_private_key(ec_key.get(), priv_bn.get()) != 1) {
        return nullptr;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key.get());
    std::unique_ptr<EC_POINT, EC_POINT_Deleter> pub_point(EC_POINT_new(group));
    if (!EC_POINT_mul(group, pub_point.get(), priv_bn.get(), nullptr, nullptr, nullptr)) {
        return nullptr;
    }

    EC_KEY_set_public_key(ec_key.get(), pub_point.get());

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(EVP_PKEY_new());
    if (!pkey) return nullptr;

    if (EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key.get()) != 1) {
        return nullptr;
    }
    ec_key.release();

    EnsureSM2Key(pkey.get());

    int pkey_id = EVP_PKEY_id(pkey.get());

    return pkey.release();
}

bool SM2EncryptTool::SM2_Encrypt(EVP_PKEY* pubkey,
                         const std::string& plaintext,
                         std::string& ciphertext) {
    if (!pubkey) return false;
    EnsureSM2Key(pubkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(pubkey, nullptr));
    if (!ctx) return false;

    bool success = false;
    if (EVP_PKEY_encrypt_init(ctx.get()) > 0) {
        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen,
                             reinterpret_cast<const unsigned char*>(plaintext.data()),
                             plaintext.size()) > 0) {
            ciphertext.resize(outlen);
            if (EVP_PKEY_encrypt(ctx.get(),
                                 reinterpret_cast<unsigned char*>(&ciphertext[0]), &outlen,
                                 reinterpret_cast<const unsigned char*>(plaintext.data()),
                                 plaintext.size()) > 0) {
                ciphertext.resize(outlen);
                success = true;
            }
        }
    }
    return success;
}

bool SM2EncryptTool::SM2_Decrypt(EVP_PKEY* privkey,
                         const std::string& ciphertext,
                         std::string& plaintext) {
    if (!privkey) return false;
    EnsureSM2Key(privkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(privkey, nullptr));
    if (!ctx) return false;

    bool success = false;
    if (EVP_PKEY_decrypt_init(ctx.get()) > 0) {
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen,
                             reinterpret_cast<const unsigned char*>(ciphertext.data()),
                             ciphertext.size()) > 0) {
            plaintext.resize(outlen);
            if (EVP_PKEY_decrypt(ctx.get(),
                                 reinterpret_cast<unsigned char*>(&plaintext[0]), &outlen,
                                 reinterpret_cast<const unsigned char*>(ciphertext.data()),
                                 ciphertext.size()) > 0) {
                plaintext.resize(outlen);
                success = true;
            }
        }
    }
    return success;
}

bool SM2EncryptTool::SM2_Sign(EVP_PKEY* privkey,
                      const std::string& message,
                      std::string& signature) {
    if (!privkey) return false;

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(privkey, nullptr));
    if (!ctx) return false;

    if (EVP_PKEY_sign_init(ctx.get()) <= 0) {
        return false;
    }

    size_t siglen = 0;
    if (EVP_PKEY_sign(ctx.get(), nullptr, &siglen,
                      reinterpret_cast<const unsigned char*>(message.data()),
                      message.size()) <= 0) {
        return false;
    }

    signature.resize(siglen);
    if (EVP_PKEY_sign(ctx.get(),
                      reinterpret_cast<unsigned char*>(&signature[0]), &siglen,
                      reinterpret_cast<const unsigned char*>(message.data()),
                      message.size()) <= 0) {
        return false;
    }

    signature.resize(siglen);
    return true;
}

bool SM2EncryptTool::SM2_Verify(EVP_PKEY* pubkey,
                        const std::string& message,
                        const std::string& signature) {
    if (!pubkey) {
        std::cout << "[SM2_Verify] pubkey is null" << std::endl;
        return false;
    }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(pubkey, nullptr));
    if (!ctx) {
        std::cout << "[SM2_Verify] EVP_PKEY_CTX_new failed" << std::endl;
        return false;
    }

    if (EVP_PKEY_verify_init(ctx.get()) <= 0) {
        std::cout << "[SM2_Verify] EVP_PKEY_verify_init failed" << std::endl;
        return false;
    }

    int ret = EVP_PKEY_verify(ctx.get(),
                              reinterpret_cast<const unsigned char*>(signature.data()),
                              signature.size(),
                              reinterpret_cast<const unsigned char*>(message.data()),
                              message.size());

    if (ret == 1) {
        std::cout << "[SM2_Verify] Signature valid" << std::endl;
        return true;
    } else if (ret == 0) {
        std::cout << "[SM2_Verify] Signature invalid" << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    } else {
        std::cout << "[SM2_Verify] error: " << GetOpenSSLError() << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
}

static void print_hex(const std::vector<unsigned char>& data, const std::string& name) {
    std::cout << "  " << name << " (" << data.size() << " bytes): ";
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cout << std::dec << std::endl;
}

static bool read_length(const std::vector<unsigned char>& data, size_t& pos, size_t& len) {
    if (pos >= data.size()) {
        return false;
    }
    
    unsigned char len_byte = data[pos++];  
    
    if (len_byte < 0x80) {
        len = len_byte;
        return true;
    }
    
    size_t num_bytes = len_byte & 0x7F;
    
    if (num_bytes == 0 || num_bytes > 4) {
        return false;
    }
    
    size_t length = 0;
    for (size_t i = 0; i < num_bytes; ++i) {
        if (pos >= data.size()) {
            return false;
        }
        length = (length << 8) | data[pos++];
    }
    
    len = length;
    return true;
}

static bool read_tlv_general(const std::vector<unsigned char>& data, size_t& pos, std::vector<unsigned char>& value, const std::string& context) {    
    if (pos >= data.size()) {
        return false;
    }
    unsigned char tag = data[pos++];
    
    if (tag != 0x02 && tag != 0x04 && tag != 0x30) {
        return false;
    }
    
    size_t len;
    if (!read_length(data, pos, len)) return false;
    
    if (pos + len > data.size()) {
        return false;
    }
    
    value.assign(data.begin() + pos, data.begin() + pos + len);
    pos += len;  
    return true;
}

static bool normalize_integer(const std::vector<unsigned char>& der_int, size_t target_len, std::vector<unsigned char>& out) {
    if (der_int.empty()) {
        return false;
    }
    
    std::vector<unsigned char> val = der_int;
    
    if (val.size() > 1 && val[0] == 0x00) {
        if ((val[1] & 0x80) != 0) {
            val.erase(val.begin()); 
        }
    }
    
    if (val.size() > target_len) {
        return false;
    }
    
    out.assign(target_len, 0x00);
    std::copy(val.begin(), val.end(), out.begin() + (target_len - val.size()));
    return true;
}

static bool encode_integer(const std::vector<unsigned char>& fixed_bytes, std::vector<unsigned char>& out) {
    std::vector<unsigned char> val;
    
    size_t start = 0;
    while (start < fixed_bytes.size() && fixed_bytes[start] == 0x00) {
        ++start;
    }
    
    if (start == fixed_bytes.size()) {
        val = {0x00};
    } else {
        val.assign(fixed_bytes.begin() + start, fixed_bytes.end());
        if ((val[0] & 0x80) != 0) {
            val.insert(val.begin(), 0x00);
        }
    }
    
    out.swap(val);
    return true;
}

static void write_length(std::vector<unsigned char>& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<unsigned char>(len));
    } else {
        size_t bytes = 0;
        size_t tmp = len;
        while (tmp > 0) {
            ++bytes;
            tmp >>= 8;
        }
        out.push_back(static_cast<unsigned char>(0x80 | bytes));

        for (size_t i = bytes; i > 0; --i) {
            unsigned char b = static_cast<unsigned char>((len >> (8 * (i - 1))) & 0xFF);
            out.push_back(b);
        }
    }
}

static void write_integer(std::vector<unsigned char>& out, const std::vector<unsigned char>& value, const std::string& name) {
    out.push_back(0x02);                  
    write_length(out, value.size());        
    out.insert(out.end(), value.begin(), value.end()); 
}

static void write_octet_string(std::vector<unsigned char>& out, const std::vector<unsigned char>& value, const std::string& name) {
    out.push_back(0x04);                 
    write_length(out, value.size());       
    out.insert(out.end(), value.begin(), value.end());  
}

bool SM2EncryptTool::SM2_DER_to_C1C3C2(const std::string& derCipher, std::string& rawCipher) {
    std::vector<unsigned char> derVec(derCipher.begin(), derCipher.end());

    size_t pos = 0;
    std::vector<unsigned char> seq;

    if (!read_tlv_general(derVec, pos, seq, "top-level SEQUENCE")) return false;

    if (pos != derVec.size()) {
        return false;
    }

    pos = 0;

    std::vector<unsigned char> x_int;
    if (!read_tlv_general(seq, pos, x_int, "xCoordinate")) return false;

    std::vector<unsigned char> y_int;
    if (!read_tlv_general(seq, pos, y_int, "yCoordinate")) return false;

    std::vector<unsigned char> x, y;
    if (!normalize_integer(x_int, 32, x)) return false;
    if (!normalize_integer(y_int, 32, y)) return false;

    std::vector<unsigned char> c3;
    if (!read_tlv_general(seq, pos, c3, "hash")) return false;

    std::vector<unsigned char> c2;
    if (!read_tlv_general(seq, pos, c2, "cipherText")) return false;

    if (pos != seq.size()) {
        return false;
    }

    std::vector<unsigned char> c1;
    c1.push_back(0x04);
    c1.insert(c1.end(), x.begin(), x.end());
    c1.insert(c1.end(), y.begin(), y.end());

    std::vector<unsigned char> rawVec;
    rawVec.reserve(c1.size() + c3.size() + c2.size());
    rawVec.insert(rawVec.end(), c1.begin(), c1.end());
    rawVec.insert(rawVec.end(), c3.begin(), c3.end());
    rawVec.insert(rawVec.end(), c2.begin(), c2.end());

    rawCipher.assign(rawVec.begin(), rawVec.end());
    return true;
}

bool SM2EncryptTool::SM2_C1C3C2_to_DER(const std::string& rawCipher, std::string& derCipher) {
    std::vector<unsigned char> rawVec(rawCipher.begin(), rawCipher.end());

    if (rawVec.size() < 1 + 32 + 32 + 32) {
        return false;
    }
    if (rawVec[0] != 0x04) {
        return false;
    }

    std::vector<unsigned char> x(rawVec.begin() + 1, rawVec.begin() + 1 + 32);
    std::vector<unsigned char> y(rawVec.begin() + 1 + 32, rawVec.begin() + 1 + 64);
    std::vector<unsigned char> c3(rawVec.begin() + 65, rawVec.begin() + 65 + 32);
    std::vector<unsigned char> c2(rawVec.begin() + 65 + 32, rawVec.end());

    std::vector<unsigned char> x_int, y_int;
    if (!encode_integer(x, x_int)) return false;
    if (!encode_integer(y, y_int)) return false;

    std::vector<unsigned char> seq_content;
    write_integer(seq_content, x_int, "x");
    write_integer(seq_content, y_int, "y");
    write_octet_string(seq_content, c3, "hash");
    write_octet_string(seq_content, c2, "cipherText");

    std::vector<unsigned char> derVec;
    derVec.push_back(0x30);                    
    write_length(derVec, seq_content.size());
    derVec.insert(derVec.end(), seq_content.begin(), seq_content.end());

    derCipher.assign(derVec.begin(), derVec.end());
    return true;
}

bool SM2EncryptTool::SM2_DER_to_RAW(const std::string& der, std::string& raw) {
    std::vector<unsigned char> derVec(der.begin(), der.end());
    size_t pos = 0;
    std::vector<unsigned char> seq;

    if (!read_tlv_general(derVec, pos, seq, "signature SEQUENCE")) return false;
    if (pos != derVec.size()) return false;  

    pos = 0;
    std::vector<unsigned char> r_int, s_int;
    if (!read_tlv_general(seq, pos, r_int, "r INTEGER")) return false;
    if (!read_tlv_general(seq, pos, s_int, "s INTEGER")) return false;
    if (pos != seq.size()) return false;

    std::vector<unsigned char> r_norm, s_norm;
    if (!normalize_integer(r_int, 32, r_norm)) return false;
    if (!normalize_integer(s_int, 32, s_norm)) return false;

    std::vector<unsigned char> rawVec;
    rawVec.reserve(64);
    rawVec.insert(rawVec.end(), r_norm.begin(), r_norm.end());
    rawVec.insert(rawVec.end(), s_norm.begin(), s_norm.end());

    raw.assign(rawVec.begin(), rawVec.end());
    return true;
}

bool SM2EncryptTool::SM2_RAW_to_DER(const std::string& raw, std::string& der) {
    if (raw.size() != 64) return false;

    std::vector<unsigned char> r_bytes(raw.begin(), raw.begin() + 32);
    std::vector<unsigned char> s_bytes(raw.begin() + 32, raw.end());

    std::vector<unsigned char> r_int, s_int;
    if (!encode_integer(r_bytes, r_int)) return false;
    if (!encode_integer(s_bytes, s_int)) return false;

    std::vector<unsigned char> seq_content;
    write_integer(seq_content, r_int, "r");
    write_integer(seq_content, s_int, "s");

    std::vector<unsigned char> derVec;
    derVec.push_back(0x30);                    
    write_length(derVec, seq_content.size());
    derVec.insert(derVec.end(), seq_content.begin(), seq_content.end());

    der.assign(derVec.begin(), derVec.end());
    return true;
}