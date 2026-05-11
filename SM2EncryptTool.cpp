#include "SM2EncryptTool.h"
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

// 获取 OpenSSL 错误字符串
std::string GetOpenSSLError() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

// 确保 SM2 密钥在 1.1.1 中被正确设置别名
void SM2EncryptTool::EnsureSM2Key(EVP_PKEY* pkey) {
    if (!pkey) return;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    // OpenSSL 1.1.1 需要手动设置类型别名
    int nid = EVP_PKEY_id(pkey);
    if (nid == EVP_PKEY_EC) {
        EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (ec && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) == NID_sm2) {
            if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) == 1)
            {
            }
            int pkey_type = EVP_PKEY_id(pkey);
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
    EnsureSM2Key(privkey);

    EVP_MD_CTX* md_ctx = nullptr;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    const char* sm2_id = "1234567812345678";
    bool success = false;
    size_t sig_len = 0;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) goto cleanup;

    pkey_ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!pkey_ctx) goto cleanup;

    if (EVP_PKEY_CTX_set1_id(pkey_ctx, (const unsigned char*)sm2_id, strlen(sm2_id)) <= 0)
        goto cleanup;

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sm3(), nullptr, privkey) <= 0)
        goto cleanup;

    // 传入原始消息（string 类型，使用 data() 和 size()）
    if (EVP_DigestSignUpdate(md_ctx, message.data(), message.size()) <= 0)
        goto cleanup;

    if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) <= 0)
        goto cleanup;

    signature.resize(sig_len);
    if (EVP_DigestSignFinal(md_ctx, reinterpret_cast<unsigned char*>(&signature[0]), &sig_len) <= 0)
        goto cleanup;

    signature.resize(sig_len);
    success = true;

cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    // pkey_ctx 会被 md_ctx 释放，无需手动释放
    return success;
}

bool SM2EncryptTool::SM2_Verify(EVP_PKEY* pubkey,
                                const std::string& message,
                                const std::string& signature) {
    if (!pubkey) {
        return false;
    }
    EnsureSM2Key(pubkey);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return false;
    }

    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    if (!pkey_ctx) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    const char* sm2_id = "1234567812345678";
    if (EVP_PKEY_CTX_set1_id(pkey_ctx, (const unsigned char*)sm2_id, strlen(sm2_id)) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

    if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sm3(), nullptr, pubkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    if (EVP_DigestVerifyUpdate(md_ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    int ret = EVP_DigestVerifyFinal(md_ctx,
                                    reinterpret_cast<const unsigned char*>(signature.data()),
                                    signature.size());
    EVP_MD_CTX_free(md_ctx);

    if (ret == 1) {
        return true;
    } else if (ret == 0) {
        ERR_print_errors_fp(stderr);
        return false;
    } else {
        ERR_print_errors_fp(stderr);
        return false;
    }
}

/**
 * 读取 DER 长度字段（出参模式）
 * 流程：
 * 1. 检查位置是否越界
 * 2. 读取第一个长度字节
 * 3. 若最高位为0，则为短编码，直接返回该值
 * 4. 若最高位为1，则为长编码，低7位表示后续字节数
 * 5. 读取指定数量的字节，组合成大端序长度值
 */
static bool read_length(const std::vector<unsigned char>& data, size_t& pos, size_t& len) {
    // 检查是否还有数据可读
    if (pos >= data.size()) {
        return false;
    }
    
    unsigned char len_byte = data[pos++];  // 读取第一个长度字节
    
    // 短编码：长度 < 128，直接使用该字节值
    if (len_byte < 0x80) {
        len = len_byte;
        return true;
    }
    
    // 长编码：低7位表示后续长度字节数
    size_t num_bytes = len_byte & 0x7F;
    
    // 长度字节数不能为0（否则无意义），也不能超过4（防止过大的长度，可根据需求调整）
    if (num_bytes == 0 || num_bytes > 4) {
        return false;
    }
    
    // 逐字节读取长度值（大端序）
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

/**
 * 读取通用的 DER TLV 结构（出参模式）
 * 流程：
 * 1. 检查位置，读取标签字节
 * 2. 验证标签是否为允许的类型（0x02 INTEGER, 0x04 OCTET STRING, 0x30 SEQUENCE）
 * 3. 调用 read_length 读取长度
 * 4. 根据长度截取值部分
 * 5. 更新位置
 */
static bool read_tlv_general(const std::vector<unsigned char>& data, size_t& pos, std::vector<unsigned char>& value, const std::string& context) {    
    // 读取标签字节
    if (pos >= data.size()) {
        return false;
    }
    unsigned char tag = data[pos++];
    
    // 仅允许 INTEGER (0x02), OCTET STRING (0x04), SEQUENCE (0x30)
    if (tag != 0x02 && tag != 0x04 && tag != 0x30) {
        return false;
    }
    
    // 读取长度
    size_t len;
    if (!read_length(data, pos, len)) return false;
    
    // 检查数据是否足够
    if (pos + len > data.size()) {
        return false;
    }
    
    // 提取值部分
    value.assign(data.begin() + pos, data.begin() + pos + len);
    pos += len;  // 移动位置到下一个TLV开始
    return true;
}

/**
 * 将 INTEGER 的 DER 编码值规范化为固定长度（如32字节）
 * 流程：
 * 1. 如果DER值有前导0x00且下一个字节最高位为1，则去掉这个前导0（这是DER中表示正数的做法）
 * 2. 如果处理后的长度超过目标长度，则报错
 * 3. 在左侧补零至目标长度
 */
static bool normalize_integer(const std::vector<unsigned char>& der_int, size_t target_len, std::vector<unsigned char>& out) {
    // 空值非法
    if (der_int.empty()) {
        return false;
    }
    
    std::vector<unsigned char> val = der_int;
    
    // 去除可能的前导0x00（用于表示正数的情况）
    // 条件：长度>=2，第一个字节为0，且第二个字节的最高位为1
    if (val.size() > 1 && val[0] == 0x00) {
        if ((val[1] & 0x80) != 0) {
            val.erase(val.begin());  // 删除前导0
        }
    }
    
    // 检查长度是否超出目标
    if (val.size() > target_len) {
        return false;
    }
    
    // 在左侧补零至目标长度
    out.assign(target_len, 0x00);
    std::copy(val.begin(), val.end(), out.begin() + (target_len - val.size()));
    return true;
}

/**
 * 将固定长度（如32字节）的字节数组编码为 INTEGER DER 值部分（不含标签和长度）
 * 流程：
 * 1. 跳过前导零（保留至少一个零如果全为零）
 * 2. 检查结果值的最高位：若为1，则需要在前面添加0x00以表示正数
 * 3. 输出最终的值部分
 */
static bool encode_integer(const std::vector<unsigned char>& fixed_bytes, std::vector<unsigned char>& out) {
    std::vector<unsigned char> val;
    
    // 跳过前导零（但保留一个零如果全部为零）
    size_t start = 0;
    while (start < fixed_bytes.size() && fixed_bytes[start] == 0x00) {
        ++start;
    }
    
    // 如果全部为零，则编码为单字节0x00
    if (start == fixed_bytes.size()) {
        val = {0x00};
    } else {
        // 截取有效部分
        val.assign(fixed_bytes.begin() + start, fixed_bytes.end());
        // 如果最高位为1，添加前导0x00表示正数
        if ((val[0] & 0x80) != 0) {
            val.insert(val.begin(), 0x00);
        }
    }
    
    out.swap(val);
    return true;
}

/**
 * 写入 DER 长度字段（修改输出缓冲区）
 * 流程：
 * 1. 如果长度 < 128，直接写一个字节
 * 2. 否则，计算需要多少个字节表示长度，第一个字节为0x80|字节数，后面跟长度的大端序表示
 */
static void write_length(std::vector<unsigned char>& out, size_t len) {
    if (len < 0x80) {
        // 短编码：直接写入长度值
        out.push_back(static_cast<unsigned char>(len));
    } else {
        // 长编码：计算需要多少个字节表示长度
        size_t bytes = 0;
        size_t tmp = len;
        while (tmp > 0) {
            ++bytes;
            tmp >>= 8;
        }
        // 写入第一个字节：最高位为1，低7位表示后续字节数
        out.push_back(static_cast<unsigned char>(0x80 | bytes));

        // 按大端序写入长度值
        for (size_t i = bytes; i > 0; --i) {
            unsigned char b = static_cast<unsigned char>((len >> (8 * (i - 1))) & 0xFF);
            out.push_back(b);
        }
    }
}

/**
 * 写入 INTEGER 类型的 TLV（标签、长度、值）
 * 流程：
 * 1. 写入标签 0x02
 * 2. 写入长度（调用 write_length）
 * 3. 写入值部分
 */
static void write_integer(std::vector<unsigned char>& out, const std::vector<unsigned char>& value, const std::string& name) {
    out.push_back(0x02);                    // INTEGER 标签
    write_length(out, value.size());        // 长度
    out.insert(out.end(), value.begin(), value.end());  // 值
}

/**
 * 写入 OCTET STRING 类型的 TLV（标签、长度、值）
 * 流程：
 * 1. 写入标签 0x04
 * 2. 写入长度
 * 3. 写入值
 */
static void write_octet_string(std::vector<unsigned char>& out, const std::vector<unsigned char>& value, const std::string& name) {
    out.push_back(0x04);                    // OCTET STRING 标签
    write_length(out, value.size());        // 长度
    out.insert(out.end(), value.begin(), value.end());  // 值
}

/**
 * 将 DER 格式的 SM2 密文转换为原始 C1C3C2 格式
 * 流程：
 * 1. 解析顶层 SEQUENCE，获取内容
 * 2. 依次读取 xCoordinate (INTEGER)、yCoordinate (INTEGER)、hash (OCTET STRING)、cipherText (OCTET STRING)
 * 3. 将 x、y 规范化为32字节（补零或去前导零）
 * 4. 构造 C1：0x04 + x(32) + y(32)
 * 5. 组合 C1 + C3 + C2 输出
 */
bool SM2EncryptTool::SM2_DER_to_C1C3C2(const std::string& derCipher, std::string& rawCipher) {
    // 输入字符串 → vector<unsigned char>，便于复用原有解析函数
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

    // 构造 C1
    std::vector<unsigned char> c1;
    c1.push_back(0x04);
    c1.insert(c1.end(), x.begin(), x.end());
    c1.insert(c1.end(), y.begin(), y.end());

    // 组合原始密文
    std::vector<unsigned char> rawVec;
    rawVec.reserve(c1.size() + c3.size() + c2.size());
    rawVec.insert(rawVec.end(), c1.begin(), c1.end());
    rawVec.insert(rawVec.end(), c3.begin(), c3.end());
    rawVec.insert(rawVec.end(), c2.begin(), c2.end());

    // 输出为 string
    rawCipher.assign(rawVec.begin(), rawVec.end());
    return true;
}


/**
 * 将原始 C1C3C2 格式的 SM2 密文转换为 DER 格式
 * 流程：
 * 1. 检查输入长度和点格式标识（必须是0x04）
 * 2. 提取 x (32字节)、y (32字节)、C3 (32字节)、C2 (剩余)
 * 3. 将 x、y 编码为 INTEGER 值部分（去掉前导零，必要时添加0x00）
 * 4. 构造 SEQUENCE 内容：x INTEGER + y INTEGER + C3 OCTET STRING + C2 OCTET STRING
 * 5. 添加 SEQUENCE 标签和长度，输出 DER
 */
bool SM2EncryptTool::SM2_C1C3C2_to_DER(const std::string& rawCipher, std::string& derCipher) {
    // 输入字符串 → vector
    std::vector<unsigned char> rawVec(rawCipher.begin(), rawCipher.end());

    // 校验最小长度和点格式
    if (rawVec.size() < 1 + 32 + 32 + 32) {
        return false;
    }
    if (rawVec[0] != 0x04) {
        return false;
    }

    // 提取各分量
    std::vector<unsigned char> x(rawVec.begin() + 1, rawVec.begin() + 1 + 32);
    std::vector<unsigned char> y(rawVec.begin() + 1 + 32, rawVec.begin() + 1 + 64);
    std::vector<unsigned char> c3(rawVec.begin() + 65, rawVec.begin() + 65 + 32);
    std::vector<unsigned char> c2(rawVec.begin() + 65 + 32, rawVec.end());

    // 编码 INTEGER 值部分
    std::vector<unsigned char> x_int, y_int;
    if (!encode_integer(x, x_int)) return false;
    if (!encode_integer(y, y_int)) return false;

    // 构造 SEQUENCE 内容
    std::vector<unsigned char> seq_content;
    write_integer(seq_content, x_int, "x");
    write_integer(seq_content, y_int, "y");
    write_octet_string(seq_content, c3, "hash");
    write_octet_string(seq_content, c2, "cipherText");

    // 构造最终 DER
    std::vector<unsigned char> derVec;
    derVec.push_back(0x30);                     // SEQUENCE 标签
    write_length(derVec, seq_content.size());
    derVec.insert(derVec.end(), seq_content.begin(), seq_content.end());

    // 输出为 string
    derCipher.assign(derVec.begin(), derVec.end());
    return true;
}

/**
 * DER格式签名 → 64字节裸R+S格式
 * 输入：DER编码的签名（SEQUENCE { r INTEGER, s INTEGER }）
 * 输出：raw为64字节，前32字节为r（大端），后32字节为s（大端）
 */
bool SM2EncryptTool::SM2_DER_to_RAW(const std::string& der, std::string& raw) {
    std::vector<unsigned char> derVec(der.begin(), der.end());
    size_t pos = 0;
    std::vector<unsigned char> seq;

    // 解析顶层 SEQUENCE
    if (!read_tlv_general(derVec, pos, seq, "signature SEQUENCE")) return false;
    if (pos != derVec.size()) return false;  // 确保没有多余数据

    pos = 0;
    std::vector<unsigned char> r_int, s_int;
    if (!read_tlv_general(seq, pos, r_int, "r INTEGER")) return false;
    if (!read_tlv_general(seq, pos, s_int, "s INTEGER")) return false;
    if (pos != seq.size()) return false;

    // 规范化为32字节
    std::vector<unsigned char> r_norm, s_norm;
    if (!normalize_integer(r_int, 32, r_norm)) return false;
    if (!normalize_integer(s_int, 32, s_norm)) return false;

    // 拼接原始签名
    std::vector<unsigned char> rawVec;
    rawVec.reserve(64);
    rawVec.insert(rawVec.end(), r_norm.begin(), r_norm.end());
    rawVec.insert(rawVec.end(), s_norm.begin(), s_norm.end());

    raw.assign(rawVec.begin(), rawVec.end());
    return true;
}

/**
 * 64字节裸R+S格式 → DER格式签名
 * 输入：raw为64字节，前32字节为r，后32字节为s（均为大端序）
 * 输出：DER编码的签名
 */
bool SM2EncryptTool::SM2_RAW_to_DER(const std::string& raw, std::string& der) {
    if (raw.size() != 64) return false;

    // 提取r和s的原始字节
    std::vector<unsigned char> r_bytes(raw.begin(), raw.begin() + 32);
    std::vector<unsigned char> s_bytes(raw.begin() + 32, raw.end());

    // 编码为 INTEGER 值部分（DER）
    std::vector<unsigned char> r_int, s_int;
    if (!encode_integer(r_bytes, r_int)) return false;
    if (!encode_integer(s_bytes, s_int)) return false;

    // 构造 SEQUENCE 内容
    std::vector<unsigned char> seq_content;
    write_integer(seq_content, r_int, "r");
    write_integer(seq_content, s_int, "s");

    // 构造完整 DER
    std::vector<unsigned char> derVec;
    derVec.push_back(0x30);                     // SEQUENCE 标签
    write_length(derVec, seq_content.size());
    derVec.insert(derVec.end(), seq_content.begin(), seq_content.end());

    der.assign(derVec.begin(), derVec.end());
    return true;
}