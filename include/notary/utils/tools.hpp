#pragma once
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>
#include <tuple>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include"notary/types.hpp"
#include"notary/crypto/keys.hpp"
#include"notary/tuf/repo.hpp"

namespace notary {
namespace utils {

// 将JSON对象转换为规范化字符串
std::string MarshalCanonical(const nlohmann::json& obj);

// 内部哈希计算函数
Result<std::vector<uint8_t>> _CalculateSHAHash(const std::vector<uint8_t>& data, const EVP_MD* algorithm);

// 计算数据的SHA-256哈希
Result<std::vector<uint8_t>> CalculateSHA256Hash(const std::vector<uint8_t>& data);
// 计算数据的SHA-512哈希
Result<std::vector<uint8_t>> CalculateSHA512Hash(const std::vector<uint8_t>& data);
// 检查哈希值
Error CheckHashes(const std::vector<uint8_t>& content, 
                  const std::string& roleName,
                  const std::map<std::string, std::vector<uint8_t>>& expectedHashes);   

// 将字节数组转换为十六进制字符串
std::string HexEncode(const std::vector<uint8_t>& data);
// 将十六进制字符串转换为字节数组
std::vector<uint8_t> HexDecode(const std::string& hex);

// Base64编码
std::string Base64Encode(const std::vector<uint8_t>& data);
// Base64解码
std::vector<uint8_t> Base64Decode(const std::string& base64);

// 将私钥转换为EVP_PKEY
EVP_PKEY* ConvertPrivateKeyToEVPKey(std::shared_ptr<crypto::PrivateKey> privKey);

// 将私钥转换为PKCS8格式
std::string ConvertPrivateKeyToPKCS8(
    std::shared_ptr<crypto::PrivateKey> privKey,    // 私钥
    const std::string& role,                        // 角色信息
    const std::string& gun,                         // GUN
    const std::string& passphrase = ""              // 加密密码（为空表示不加密）
);

// 从PEM数据中提取私钥属性（角色和GUN）
std::tuple<std::string, std::string, Error> extractPrivateKeyAttributes(
    const std::vector<uint8_t>& pemBytes, 
    bool fips = false
);

// 解析PEM格式的私钥
Result<std::shared_ptr<crypto::PrivateKey>> ParsePEMPrivateKey(
    const std::vector<uint8_t>& pemBytes, 
    const std::string& passphrase);

// 内部解析函数，支持FIPS模式控制
Result<std::shared_ptr<crypto::PrivateKey>> parsePEMPrivateKey(
    const std::vector<uint8_t>& pemBytes, 
    const std::string& passphrase, 
    bool fips);

// 解析传统格式私钥（RSA PRIVATE KEY, EC PRIVATE KEY等）
Result<std::shared_ptr<crypto::PrivateKey>> parseLegacyPrivateKey(
    const std::string& keyType,
    const unsigned char* data,
    long dataLen,
    const std::string& passphrase);

// 解析PKCS#8格式私钥
Result<std::shared_ptr<crypto::PrivateKey>> ParsePKCS8ToTufKey(
    const unsigned char* data,
    long dataLen,
    const char* passphrase);

// 将EVP_PKEY转换为TUF私钥对象
Result<std::shared_ptr<crypto::PrivateKey>> convertEVPKeyToTufKey(EVP_PKEY* evpKey);

// 获取父角色
std::string getParentRole(const std::string& role);
// 清理路径
std::string cleanPath(const std::string& path);
// 将vector转换为字符串表示（用于日志记录）
std::string vectorToString(const std::vector<std::string>& vec);

}
}