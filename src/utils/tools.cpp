#include "notary/utils/tools.hpp"
#include "notary/crypto/keys.hpp"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pkcs12.h>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <tuple>
#include <sstream>
#include <cctype>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/types.h>
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0755)
#endif

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

// 辅助方法：检查哈希值
Error CheckHashes(const std::vector<uint8_t>& content, 
                                  const std::string& roleName,
                                  const std::map<std::string, std::vector<uint8_t>>& expectedHashes) {
    if (expectedHashes.empty()) {
        return Error("No hashes provided for role: " + roleName);
    }
    
    // 检查SHA256哈希
    auto sha256It = expectedHashes.find("sha256");
    if (sha256It != expectedHashes.end()) {
        auto sha256Result = utils::CalculateSHA256Hash(content);
        if (!sha256Result.ok()) {
            return Error("Failed to calculate SHA256 hash: " + sha256Result.error().what());
        }
        
        if (sha256It->second != sha256Result.value()) {
            return Error("SHA256 checksum mismatch for role: " + roleName);
        }
    }
    
    // 检查SHA512哈希（如果存在）
    auto sha512It = expectedHashes.find("sha512");
    if (sha512It != expectedHashes.end()) {
        auto sha512Result = utils::CalculateSHA512Hash(content);
        if (!sha512Result.ok()) {
            return Error("Failed to calculate SHA512 hash: " + sha512Result.error().what());
        }
        
        if (sha512It->second != sha512Result.value()) {
            return Error("SHA512 checksum mismatch for role: " + roleName);
        }
    }
    
    return Error(); // 成功
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
    
    // 验证输入格式
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        
        // 验证是否为有效的十六进制字符
        for (char c : byteString) {
            if (!std::isxdigit(c)) {
                throw std::invalid_argument("Invalid hex character: " + std::string(1, c));
            }
        }
        
        try {
            data.push_back(static_cast<uint8_t>(std::stoul(byteString, nullptr, 16)));
        } catch (const std::exception& e) {
            throw std::invalid_argument("Failed to decode hex byte: " + byteString);
        }
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

    // 移除可能存在的换行符
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
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

// 将私钥转换为EVPKey
EVP_PKEY* ConvertPrivateKeyToEVPKey(std::shared_ptr<crypto::PrivateKey> privKey) {
    auto privateData = privKey->Private();
    std::string algorithm = privKey->Algorithm();
    
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return nullptr;
    
    if (algorithm == "rsa" || algorithm == "rsa-x509") {
        const unsigned char* p = privateData.data();
        RSA* rsa = d2i_RSAPrivateKey(nullptr, &p, privateData.size());
        if (!rsa || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            EVP_PKEY_free(pkey);
            return nullptr;
        }
    } else if (algorithm == "ecdsa" || algorithm == "ecdsa-x509") {
        const unsigned char* p = privateData.data();
        EC_KEY* ec = d2i_ECPrivateKey(nullptr, &p, privateData.size());
        if (!ec || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
            EVP_PKEY_free(pkey);
            return nullptr;
        }
    }
    
    return pkey;
}


std::string ConvertPrivateKeyToPKCS8(
    std::shared_ptr<crypto::PrivateKey> privKey,                           // 私钥（EVP 封装）
    const std::string& role,                 // 角色信息
    const std::string& gun,                  // GUN
    const std::string& passphrase       // 加密密码（为空表示不加密）
) {

    EVP_PKEY* pkey = ConvertPrivateKeyToEVPKey(privKey);
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) throw std::runtime_error("BIO 分配失败");

    int rc = 0;
    if (passphrase.empty()) {
        // 未加密的 PKCS#8 私钥 PEM
        rc = PEM_write_bio_PKCS8PrivateKey(
            mem, pkey, nullptr, nullptr, 0, nullptr, nullptr
        );
    } else {
        // 使用 AES-256-CBC 加密 PKCS#8
        rc = PEM_write_bio_PKCS8PrivateKey(
            mem, pkey,
            EVP_aes_256_cbc(),
            passphrase.c_str(),
            passphrase.size(),
            nullptr, nullptr
        );
    }

    if (rc != 1) {
        BIO_free(mem);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("PKCS#8 写入失败");
    }

    // 获取 PEM 数据
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string pemData(bptr->data, bptr->length);
    BIO_free(mem);
    EVP_PKEY_free(pkey);

     // 使用标准PEM头部格式（小写，冒号后有空格）
    std::string header;
    if (!role.empty()) {
        header += "role: " + role + "\n";  // 小写 "role"
    }
    if (!gun.empty()) {
        header += "gun: " + gun + "\n";    // 小写 "gun"
    }
    
    if (!header.empty()) {
        header += "\n";  // 头部后添加空行
        size_t insertPos = pemData.find('\n') + 1;
        pemData.insert(insertPos, header);
    }

    return pemData;
}

// 从PEM数据中提取私钥属性（角色和GUN）
std::tuple<RoleName, std::string, Error> extractPrivateKeyAttributes(
    const std::vector<uint8_t>& pemBytes, 
    bool fips) {
    
    std::string pemStr(pemBytes.begin(), pemBytes.end());
    
    // 查找PEM块的开始和结束
    size_t beginPos = pemStr.find("-----BEGIN ");
    size_t endHeaderPos = pemStr.find("-----", beginPos + 11);
    
    if (beginPos == std::string::npos || endHeaderPos == std::string::npos) {
        return std::make_tuple(RoleName::TargetsRole, "", Error("PEM block is empty"));
    }
    
    // 提取块类型
    std::string blockType = pemStr.substr(beginPos + 11, endHeaderPos - beginPos - 11);
    
    // 检查FIPS模式下不支持的密钥类型
    if (fips) {
        if (blockType == "RSA PRIVATE KEY" || 
            blockType == "EC PRIVATE KEY" || 
            blockType == "ED25519 PRIVATE KEY") {
            return std::make_tuple(RoleName::TargetsRole, "", 
                Error(blockType + " not supported in FIPS mode"));
        }
    }
    
    // 验证密钥格式
    if (blockType != "RSA PRIVATE KEY" && 
        blockType != "EC PRIVATE KEY" && 
        blockType != "ED25519 PRIVATE KEY" &&
        blockType != "PRIVATE KEY" && 
        blockType != "ENCRYPTED PRIVATE KEY") {
        return std::make_tuple(RoleName::TargetsRole, "", Error("unknown key format"));
    }
    
    // 查找头部信息（在第一行-----END之后到空行之前）
    size_t headerStart = pemStr.find('\n', endHeaderPos) + 1;
    size_t dataStart = pemStr.find("\n\n", headerStart);
    
    if (dataStart == std::string::npos) {
        dataStart = pemStr.find('\n', headerStart);
        if (dataStart != std::string::npos && 
            pemStr.substr(dataStart + 1, 5) != "-----") {
            // 没有头部信息，直接是数据
            return std::make_tuple(RoleName::TargetsRole, "", Error());
        }
    }
    
    RoleName role = RoleName::TargetsRole;
    std::string gun = "";
    
    if (dataStart != std::string::npos && dataStart > headerStart) {
        std::string headers = pemStr.substr(headerStart, dataStart - headerStart);
        
        // 解析头部信息
        std::istringstream headerStream(headers);
        std::string line;
        
        while (std::getline(headerStream, line)) {
            if (line.empty()) break;
            
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 1);
                
                // 去除前后空格
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                if (key == "role") {
                    role = stringToRole(value);
                } else if (key == "gun") {
                    gun = value;
                }
            }
        }
    }
    
    return std::make_tuple(role, gun, Error());
}

// 解析PEM格式的私钥
Result<std::shared_ptr<crypto::PrivateKey>> ParsePEMPrivateKey(
    const std::vector<uint8_t>& pemBytes, 
    const std::string& passphrase) {
    return parsePEMPrivateKey(pemBytes, passphrase, false); // 默认非FIPS模式
}

// 内部解析函数，支持FIPS模式控制
Result<std::shared_ptr<crypto::PrivateKey>> parsePEMPrivateKey(
    const std::vector<uint8_t>& pemBytes, 
    const std::string& passphrase, 
    bool fips) {
    
    std::string pemStr(pemBytes.begin(), pemBytes.end());
    
    // 使用OpenSSL的BIO来解析PEM
    BIO* bio = BIO_new_mem_buf(pemStr.data(), static_cast<int>(pemStr.size()));
    if (!bio) {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("Failed to create BIO from PEM data"));
    }
    
    // 解析PEM块
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* data = nullptr;
    long dataLen = 0;
    
    if (!PEM_read_bio(bio, &name, &header, &data, &dataLen)) {
        BIO_free(bio);
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("no valid private key found"));
    }
    
    std::string blockType(name);
    BIO_free(bio);
    
    // 检查密钥类型
    if (blockType == "RSA PRIVATE KEY" || 
        blockType == "EC PRIVATE KEY" || 
        blockType == "ED25519 PRIVATE KEY") {
        
        if (fips) {
            OPENSSL_free(name);
            OPENSSL_free(header);
            OPENSSL_free(data);
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error(blockType + " not supported in FIPS mode"));
        }
        
        // 解析传统格式私钥
        auto result = parseLegacyPrivateKey(blockType, data, dataLen, passphrase);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        return result;
        
    } else if (blockType == "ENCRYPTED PRIVATE KEY" || blockType == "PRIVATE KEY") {
        
        // 解析PKCS#8格式私钥
        auto result = ParsePKCS8ToTufKey(data, dataLen, 
            passphrase.empty() ? nullptr : passphrase.c_str());
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        return result;
        
    } else {
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("unsupported key type: " + blockType));
    }
}

// 解析传统格式私钥（RSA PRIVATE KEY, EC PRIVATE KEY等）
Result<std::shared_ptr<crypto::PrivateKey>> parseLegacyPrivateKey(
    const std::string& keyType,
    const unsigned char* data,
    long dataLen,
    const std::string& passphrase) {
    
    EVP_PKEY* evpKey = nullptr;
    
    if (keyType == "RSA PRIVATE KEY") {
        // 解析RSA私钥
        const unsigned char* p = data;
        RSA* rsa = d2i_RSAPrivateKey(nullptr, &p, dataLen);
        if (!rsa) {
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to parse RSA private key"));
        }
        
        evpKey = EVP_PKEY_new();
        if (!evpKey || EVP_PKEY_assign_RSA(evpKey, rsa) != 1) {
            RSA_free(rsa);
            EVP_PKEY_free(evpKey);
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to create EVP_PKEY from RSA key"));
        }
        
    } else if (keyType == "EC PRIVATE KEY") {
        // 解析ECDSA私钥
        const unsigned char* p = data;
        EC_KEY* ec = d2i_ECPrivateKey(nullptr, &p, dataLen);
        if (!ec) {
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to parse EC private key"));
        }
        
        evpKey = EVP_PKEY_new();
        if (!evpKey || EVP_PKEY_assign_EC_KEY(evpKey, ec) != 1) {
            EC_KEY_free(ec);
            EVP_PKEY_free(evpKey);
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to create EVP_PKEY from EC key"));
        }
        
    } else if (keyType == "ED25519 PRIVATE KEY") {
        // 解析ED25519私钥
        evpKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, data, dataLen);
        if (!evpKey) {
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to parse ED25519 private key"));
        }
        
    } else {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("Unsupported legacy key type: " + keyType));
    }
    
    // 将EVP_PKEY转换为TUF私钥对象
    auto tufKey = convertEVPKeyToTufKey(evpKey);
    EVP_PKEY_free(evpKey);
    
    return tufKey;
}

// 解析PKCS#8格式私钥
Result<std::shared_ptr<crypto::PrivateKey>> ParsePKCS8ToTufKey(
    const unsigned char* data,
    long dataLen,
    const char* passphrase) {
    
    EVP_PKEY* evpKey = nullptr;
    
    if (passphrase == nullptr) {
        // 未加密的PKCS#8私钥
        const unsigned char* p = data;
        PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, dataLen);
        if (!p8inf) {
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to parse PKCS#8 private key"));
        }
        
        evpKey = EVP_PKCS82PKEY(p8inf);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        
    } else {
        // 加密的PKCS#8私钥
        const unsigned char* p = data;
        X509_SIG* p8 = d2i_X509_SIG(nullptr, &p, dataLen);
        if (!p8) {
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to parse encrypted PKCS#8 private key"));
        }
        
        PKCS8_PRIV_KEY_INFO* p8inf = PKCS8_decrypt(p8, passphrase, strlen(passphrase));
        X509_SIG_free(p8);
        
        if (!p8inf) {
            return Result<std::shared_ptr<crypto::PrivateKey>>(
                Error("Failed to decrypt PKCS#8 private key - wrong passphrase?"));
        }
        
        evpKey = EVP_PKCS82PKEY(p8inf);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
    }
    
    if (!evpKey) {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("Failed to extract private key from PKCS#8"));
    }
    
    // 将EVP_PKEY转换为TUF私钥对象
    auto tufKey = convertEVPKeyToTufKey(evpKey);
    EVP_PKEY_free(evpKey);
    
    return tufKey;
}

// 将EVP_PKEY转换为TUF私钥对象
Result<std::shared_ptr<crypto::PrivateKey>> convertEVPKeyToTufKey(EVP_PKEY* evpKey) {
    if (!evpKey) {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("EVP_PKEY is null"));
    }
    
    int keyType = EVP_PKEY_base_id(evpKey);
    
    // 获取私钥DER数据
    unsigned char* privDer = nullptr;
    int privDerLen = i2d_PrivateKey(evpKey, &privDer);
    if (privDerLen <= 0) {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("Failed to serialize private key to DER"));
    }
    
    std::vector<uint8_t> privateData(privDer, privDer + privDerLen);
    OPENSSL_free(privDer);
    
    // 获取公钥DER数据
    unsigned char* pubDer = nullptr;
    int pubDerLen = i2d_PUBKEY(evpKey, &pubDer);
    if (pubDerLen <= 0) {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("Failed to serialize public key to DER"));
    }
    
    std::vector<uint8_t> publicData(pubDer, pubDer + pubDerLen);
    OPENSSL_free(pubDer);
    
    // 根据密钥类型创建相应的TUF密钥对象
    try {
        switch (keyType) {
            // case EVP_PKEY_RSA: {
                // auto publicKey = std::make_shared<crypto::RSAPublicKey>(publicData);
                // return Result<std::shared_ptr<crypto::PrivateKey>>(
                //     std::make_shared<crypto::RSAPrivateKey>(publicKey, privateData));
            // }
            case EVP_PKEY_EC: {
                auto publicKey = std::make_shared<crypto::ECDSAPublicKey>(publicData);
                return Result<std::shared_ptr<crypto::PrivateKey>>(
                    std::make_shared<crypto::ECDSAPrivateKey>(publicKey, privateData));
            }
            // case EVP_PKEY_ED25519: {
                // auto publicKey = std::make_shared<crypto::ED25519PublicKey>(publicData);
                // return Result<std::shared_ptr<crypto::PrivateKey>>(
                //     std::make_shared<crypto::ED25519PrivateKey>(publicKey, privateData));
            // }
            default:
                return Result<std::shared_ptr<crypto::PrivateKey>>(
                    Error("Unsupported key type: " + std::to_string(keyType)));
        }
    } catch (const std::exception& e) {
        return Result<std::shared_ptr<crypto::PrivateKey>>(
            Error("Failed to create TUF key: " + std::string(e.what())));
    }
}


// 辅助函数：清理路径，移除 ., .., 多余的斜杠和尾随斜杠 (对应Go的path.Clean)
std::string cleanPath(const std::string& path) {
    if (path.empty()) {
        return ".";
    }
    
    std::vector<std::string> parts;
    std::stringstream ss(path);
    std::string part;
    
    // 分割路径
    while (std::getline(ss, part, '/')) {
        if (part.empty() || part == ".") {
            continue; // 跳过空部分和当前目录
        } else if (part == "..") {
            if (!parts.empty() && parts.back() != "..") {
                parts.pop_back(); // 回到上级目录
            } else if (!path.empty() && path[0] != '/') {
                parts.push_back(part); // 相对路径保留..
            }
        } else {
            parts.push_back(part);
        }
    }
    
    // 重建路径
    std::string result;
    if (path[0] == '/') {
        result = "/"; // 绝对路径
    }
    
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0 || result == "/") {
            result += "/";
        }
        result += parts[i];
    }
    
    // 如果结果为空且原路径不是根目录，返回"."
    if (result.empty() && path != "/") {
        result = ".";
    }
    
    return result;
}

// 辅助函数：获取父角色 (对应Go的role.Parent())
RoleName getParentRole(RoleName role) {
    std::string strRole = roleToString(role);
    size_t lastSlash = strRole.find_last_of('/');
    
    if (lastSlash == std::string::npos) {
        // 没有找到斜杠，返回空角色或根角色
        return RoleName::RootRole; // 或者可以定义一个空角色
    }
    
    std::string parentStr = strRole.substr(0, lastSlash);
    return stringToRole(parentStr);
}
}
}