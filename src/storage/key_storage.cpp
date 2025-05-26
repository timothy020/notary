#include "notary/storage/key_storage.hpp"
#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "notary/utils/tools.hpp"
#include "notary/utils/logger.hpp"

#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/types.h>
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0755)
#endif

namespace notary {
namespace storage {

// 检查目录是否存在
bool dirExists(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR) != 0;
}

// 创建目录
bool createDir(const std::string& path) {
    return MKDIR(path.c_str()) == 0;
}

// 递归创建目录
bool createDirRecursive(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    
    if (dirExists(path)) {
        return true;
    }
    
    std::string parentPath;
    size_t pos = path.find_last_of('/');
    if (pos != std::string::npos) {
        parentPath = path.substr(0, pos);
        if (!parentPath.empty() && !dirExists(parentPath)) {
            if (!createDirRecursive(parentPath)) {
                return false;
            }
        }
    }
    
    return createDir(path);
}

Error KeyStore::Save(RoleName role, const std::string& keyID, 
                                  const std::vector<uint8_t>& encryptedKey) {
    try {
        // 保存到内存
        keyStorage_[keyID] = encryptedKey;
        roleMap_[keyID] = role;
        
        // 将密钥保存到文件
        // 创建密钥文件夹
        std::string trustDir = "./trust";
        if (!dirExists(trustDir)) {
            if (!createDirRecursive(trustDir)) {
                return Error("Failed to create trust directory: " + trustDir);
            }
        }
        
        std::string keysDir = trustDir + "/private";
        if (!dirExists(keysDir)) {
            if (!createDirRecursive(keysDir)) {
                return Error("Failed to create keys directory: " + keysDir);
            }
        }
        
        // 获取角色名称（用于文件内容中的标记）
        std::string roleName;
        switch (role) {
            case RoleName::RootRole: roleName = "root"; break;
            case RoleName::TargetsRole: roleName = "targets"; break;
            case RoleName::SnapshotRole: roleName = "snapshot"; break;
            case RoleName::TimestampRole: roleName = "timestamp"; break;
            default: roleName = "unknown"; break;
        }
        
        // 注意：TimestampRole可能由服务器管理，因此可能不需要本地存储
        // 但为了完整性，我们仍然保存它
        
        // 使用keyID作为文件名
        std::string keyPath = keysDir + "/" + keyID + ".key";
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            return Error("Failed to create key file: " + keyPath);
        }
        
        // 写入密钥文件头
        keyFile << "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
        keyFile << "role: " << roleName << "\n\n";
        
        // 将二进制数据编码为base64格式
        std::string base64Key = utils::Base64Encode(encryptedKey);
        keyFile << base64Key;
        keyFile << "-----END ENCRYPTED PRIVATE KEY-----\n";
        
        // 释放资源
        keyFile.close();
        
        // 记录日志
        utils::GetLogger().Info("base64Key: " + base64Key);
        
        return Error();
    } catch (const std::exception& e) {
        return Error(std::string("Failed to save key: ") + e.what());
    }
}

// 添加新的辅助方法
void KeyStore::MapRoleToKeyID(RoleName role, const std::string& keyID) {
    roleMap_[keyID] = role;
}

Result<std::vector<uint8_t>> KeyStore::Load(const std::string& keyID) {
    // 从存储中获取密钥
    auto it = keyStorage_.find(keyID);
    if (it == keyStorage_.end()) {
        return Result<std::vector<uint8_t>>(Error("Key not found: " + keyID));
    }
    
    return Result<std::vector<uint8_t>>(it->second);
}

std::vector<uint8_t> KeyStore::deriveKey(const std::string& passphrase) {
    // TODO: 实现基于 PBKDF2 的密钥派生
    return std::vector<uint8_t>();
}

// 实现KeyStore的ListKeys和ListAllKeys方法
std::vector<std::string> KeyStore::ListKeys(RoleName role) {
    std::vector<std::string> keys;
    for (const auto& pair : roleMap_) {
        if (pair.second == role) {
            keys.push_back(pair.first);
        }
    }
    return keys;
}

std::map<std::string, RoleName> KeyStore::ListAllKeys() {
    return roleMap_;
}

} // namespace storage
} // namespace notary