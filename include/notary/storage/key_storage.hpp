#pragma once

#include <string>
#include <vector>
#include <map>
#include <notary/types.hpp>

namespace notary {
namespace storage {

class KeyStore {
    public:
        Error Save(RoleName role, const std::string& keyID,
                  const std::vector<uint8_t>& encryptedKey);
        Result<std::vector<uint8_t>> Load(const std::string& keyID);
        
        // 生成密钥ID已不再需要，改为保存映射关系
        void MapRoleToKeyID(RoleName role, const std::string& keyID);
        
        // 列出指定角色的所有密钥
        std::vector<std::string> ListKeys(RoleName role);
        
        // 列出所有密钥
        std::map<std::string, RoleName> ListAllKeys();
        
    private:
        static constexpr auto KEY_ENCRYPTION_ALGO = "AES-256-GCM";
        std::vector<uint8_t> deriveKey(const std::string& passphrase);
        
        std::vector<uint8_t> salt_;
        int iterations_ = 100000;
        
        // 内存中密钥存储
        std::map<std::string, std::vector<uint8_t>> keyStorage_;
        std::map<std::string, RoleName> roleMap_;
};
        
} // namespace storage
} // namespace notary