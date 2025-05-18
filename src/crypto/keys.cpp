#include "notary/crypto/keys.hpp"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace notary {
namespace crypto {

std::string ECDSAPublicKey::ID() const {
    // 使用EVP接口计算SHA256哈希
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    // 检查公钥数据是否为空
    if (derData_.empty()) {
        std::cerr << "警告: 尝试为空的公钥数据计算ID" << std::endl;
        return "";
    }
    
    // 创建摘要上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "错误: 无法创建EVP_MD_CTX" << std::endl;
        return "";
    }
    
    // 初始化SHA256摘要
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) {
        std::cerr << "错误: 无法初始化SHA256摘要" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // 更新数据
    if (1 != EVP_DigestUpdate(ctx, derData_.data(), derData_.size())) {
        std::cerr << "错误: 无法更新SHA256摘要数据" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // 完成摘要计算
    if (1 != EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        std::cerr << "错误: 无法完成SHA256摘要计算" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // 释放上下文
    EVP_MD_CTX_free(ctx);
    
    // 转换为十六进制字符串
    std::stringstream ss;
    for(unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

} // namespace crypto
} // namespace notary 