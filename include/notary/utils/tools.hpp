#pragma once
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include"notary/types.hpp"

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

}
}