#include "notary/types.hpp"
#include "notary/crypto/keys.hpp"
#include <map>

namespace notary {

bool BaseRole::Equals(const BaseRole& other) const {
    // 检查基本属性
    if (name_ != other.name_ || threshold_ != other.threshold_ || keys_.size() != other.keys_.size()) {
        return false;
    }
    
    // 如果密钥列表为空，直接返回true
    if (keys_.empty() && other.keys_.empty()) {
        return true;
    }
    
    // 创建密钥ID到密钥内容的映射，避免顺序敏感
    std::map<std::string, std::vector<uint8_t>> thisKeyMap;
    std::map<std::string, std::vector<uint8_t>> otherKeyMap;
    
    // 收集当前对象的密钥ID和内容
    for (const auto& key : keys_) {
        if (key) {
            std::string keyID = key->ID();
            std::vector<uint8_t> keyBytes = key->Public();
            thisKeyMap[keyID] = keyBytes;
        } else {
            // 处理空指针的情况，使用特殊标识符
            thisKeyMap["__NULL_KEY__"] = std::vector<uint8_t>();
        }
    }
    
    // 收集其他对象的密钥ID和内容
    for (const auto& key : other.keys_) {
        if (key) {
            std::string keyID = key->ID();
            std::vector<uint8_t> keyBytes = key->Public();
            otherKeyMap[keyID] = keyBytes;
        } else {
            // 处理空指针的情况，使用特殊标识符
            otherKeyMap["__NULL_KEY__"] = std::vector<uint8_t>();
        }
    }
    
    // 比较两个映射是否相等（映射比较会同时比较键和值）
    return thisKeyMap == otherKeyMap;
}

} // namespace notary