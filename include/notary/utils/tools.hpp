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


namespace notary {
namespace utils {

// 将JSON对象转换为规范化字符串
std::string MarshalCanonical(const nlohmann::json& obj);

// 计算数据的SHA-256哈希
Result<std::vector<uint8_t>> CalculateSHA256Hash(const std::vector<uint8_t>& data);
// 计算数据的SHA-512哈希
Result<std::vector<uint8_t>> CalculateSHA512Hash(const std::vector<uint8_t>& data);

// 将字节数组转换为十六进制字符串
std::string HexEncode(const std::vector<uint8_t>& data);
// 将十六进制字符串转换为字节数组
std::vector<uint8_t> HexDecode(const std::string& hex);

// Base64编码
std::string Base64Encode(const std::vector<uint8_t>& data);
// Base64解码
std::vector<uint8_t> Base64Decode(const std::string& base64);

// 将私钥转换为PKCS8格式
std::string ConvertPrivateKeyToPKCS8(
    std::shared_ptr<crypto::PrivateKey> privKey,    // 私钥
    const std::string& role,                        // 角色信息
    const std::string& gun,                         // GUN
    const std::string& passphrase = ""              // 加密密码（为空表示不加密）
);

// 从PEM数据中提取私钥属性（角色和GUN）
std::tuple<RoleName, std::string, Error> extractPrivateKeyAttributes(
    const std::vector<uint8_t>& pemBytes, 
    bool fips = false
);

// 解析PEM格式的私钥
Result<std::shared_ptr<crypto::PrivateKey>> ParsePEMPrivateKey(
    const std::vector<uint8_t>& pemBytes, 
    const std::string& passphrase);


}
}