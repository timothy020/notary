#include "notary/utils/tools.hpp"

namespace notary {
namespace utils {

std::string MarshalCanonical(const nlohmann::json& obj) {
    // 确保对象键按字典序排序
    nlohmann::json canonical = obj;
    
    // 递归排序所有对象的键
    std::function<void(nlohmann::json&)> sortKeys = [&](nlohmann::json& j) {
        if (j.is_object()) {
            // nlohmann::json默认保持插入顺序，需要重新排序
            nlohmann::json sorted = nlohmann::json::object();
            std::vector<std::string> keys;
            
            for (auto it = j.begin(); it != j.end(); ++it) {
                keys.push_back(it.key());
            }
            
            std::sort(keys.begin(), keys.end());
            
            for (const auto& key : keys) {
                sorted[key] = j[key];
                sortKeys(sorted[key]); // 递归处理嵌套对象
            }
            
            j = sorted;
        } else if (j.is_array()) {
            for (auto& element : j) {
                sortKeys(element);
            }
        }
    };
    
    sortKeys(canonical);
    
    // 使用紧凑格式输出（无空格）
    return canonical.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
}

Result<std::vector<uint8_t>> CalculateSHA256Hash(const std::vector<uint8_t>& data) {
    return _CalculateSHAHash(data, EVP_sha256());
}

Result<std::vector<uint8_t>> CalculateSHA512Hash(const std::vector<uint8_t>& data) {
    return _CalculateSHAHash(data, EVP_sha512());
}

Result<std::vector<uint8_t>> _CalculateSHAHash(const std::vector<uint8_t>& data, const EVP_MD* algorithm) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        return Error("创建MD上下文失败");
    }

    if (EVP_DigestInit_ex(mdctx, algorithm, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Error("初始化摘要失败");
    }

    if (EVP_DigestUpdate(mdctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Error("更新摘要失败");
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Error("完成摘要失败");
    }

    EVP_MD_CTX_free(mdctx);
    return std::vector<uint8_t>(hash, hash + hashLen);
}

std::string HexEncode(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < data.size(); i++) {
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<uint8_t> HexDecode(const std::string& hex) {
    std::vector<uint8_t> data;
    data.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        data.push_back(static_cast<uint8_t>(std::stoul(byteString, nullptr, 16)));
    }
    return data;
}

std::string Base64Encode(const std::vector<uint8_t>& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    // 不换行（默认 Base64 会每 64 字符换行）
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> Base64Decode(const std::string& base64) {
    BIO* bio, * b64;
    std::vector<uint8_t> decoded(base64.length());
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.length()));
    bio = BIO_push(b64, bio);

    int decodedLen = BIO_read(bio, decoded.data(), static_cast<int>(base64.length()));
    if (decodedLen < 0) {
        BIO_free_all(bio);
        throw std::runtime_error("Base64 decode failed");
    }
    decoded.resize(decodedLen);
    BIO_free_all(bio);
    return decoded;
}



}
}