#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <filesystem>
#include <algorithm>
#include "notary/utils/tools.hpp"
#include "notary/utils/logger.hpp"
#include "notary/storage/key_storage.hpp"
#include "notary/storage/storage.hpp"
#include "notary/crypto/keys.hpp"
#include "notary/utils/tools.hpp"

namespace notary {
namespace storage {


// Error KeyStore::Save(RoleName role, const std::string& keyID, 
//                                   const std::vector<uint8_t>& encryptedKey) {
//     try {
//         // 保存到内存
//         keyStorage_[keyID] = encryptedKey;
//         roleMap_[keyID] = role;
        
//         // 将密钥保存到文件
//         // 创建密钥文件夹
//         std::string trustDir = "./trust";
//         if (!dirExists(trustDir)) {
//             if (!createDirRecursive(trustDir)) {
//                 return Error("Failed to create trust directory: " + trustDir);
//             }
//         }
        
//         std::string keysDir = trustDir + "/private";
//         if (!dirExists(keysDir)) {
//             if (!createDirRecursive(keysDir)) {
//                 return Error("Failed to create keys directory: " + keysDir);
//             }
//         }
        
//         // 获取角色名称（用于文件内容中的标记）
//         std::string roleName;
//         switch (role) {
//             case RoleName::RootRole: roleName = "root"; break;
//             case RoleName::TargetsRole: roleName = "targets"; break;
//             case RoleName::SnapshotRole: roleName = "snapshot"; break;
//             case RoleName::TimestampRole: roleName = "timestamp"; break;
//             default: roleName = "unknown"; break;
//         }
        
//         // 注意：TimestampRole可能由服务器管理，因此可能不需要本地存储
//         // 但为了完整性，我们仍然保存它
        
//         // 使用keyID作为文件名
//         std::string keyPath = keysDir + "/" + keyID + ".key";
//         std::ofstream keyFile(keyPath, std::ios::binary);
//         if (!keyFile) {
//             return Error("Failed to create key file: " + keyPath);
//         }
        
//         // 写入密钥文件头
//         keyFile << "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
//         keyFile << "role: " << roleName << "\n\n";
        
//         // 将二进制数据编码为base64格式
//         std::string base64Key = utils::Base64Encode(encryptedKey);
//         keyFile << base64Key;
//         keyFile << "-----END ENCRYPTED PRIVATE KEY-----\n";
        
//         // 释放资源
//         keyFile.close();
        
//         // 记录日志
//         utils::GetLogger().Info("base64Key: " + base64Key);
        
//         return Error();
//     } catch (const std::exception& e) {
//         return Error(std::string("Failed to save key: ") + e.what());
//     }
// }

// // 添加新的辅助方法
// void KeyStore::MapRoleToKeyID(RoleName role, const std::string& keyID) {
//     roleMap_[keyID] = role;
// }

// Result<std::vector<uint8_t>> KeyStore::Load(const std::string& keyID) {
//     // 从存储中获取密钥
//     auto it = keyStorage_.find(keyID);
//     if (it == keyStorage_.end()) {
//         return Result<std::vector<uint8_t>>(Error("Key not found: " + keyID));
//     }
    
//     return Result<std::vector<uint8_t>>(it->second);
// }

// std::vector<uint8_t> KeyStore::deriveKey(const std::string& passphrase) {
//     // TODO: 实现基于 PBKDF2 的密钥派生
//     return std::vector<uint8_t>();
// }

// // 实现KeyStore的ListKeys和ListAllKeys方法
// std::vector<std::string> KeyStore::ListKeys(RoleName role) {
//     std::vector<std::string> keys;
//     for (const auto& pair : roleMap_) {
//         if (pair.second == role) {
//             keys.push_back(pair.first);
//         }
//     }
//     return keys;
// }

// std::map<std::string, RoleName> KeyStore::ListAllKeys() {
//     return roleMap_;
// }


// GenericKeyStore 实现
std::unique_ptr<GenericKeyStore> GenericKeyStore::NewKeyFileStore(
    const std::string& baseDir, 
    PassRetriever passRetriever) {
    
    auto storage = std::make_unique<FileSystemStorage>(baseDir);
    return std::make_unique<GenericKeyStore>(std::move(storage), passRetriever);
}

std::unique_ptr<GenericKeyStore> GenericKeyStore::NewKeyMemoryStore(
    PassRetriever passRetriever) {
    
    auto storage = std::make_unique<MemoryStorage>();
    return std::make_unique<GenericKeyStore>(std::move(storage), passRetriever);
}

GenericKeyStore::GenericKeyStore(std::unique_ptr<Storage> storage, PassRetriever passRetriever)
    : store_(std::move(storage)), passRetriever_(passRetriever) {
    loadKeyInfo();
}

void GenericKeyStore::loadKeyInfo() {
    keyInfoMap_ = generateKeyInfoMap();
}

std::map<std::string, KeyInfo> GenericKeyStore::generateKeyInfoMap() {
    std::map<std::string, KeyInfo> keyInfoMap;
    
    for (const auto& keyPath : store_->ListFiles()) {
        auto dataResult = store_->Get(keyPath);
        if (!dataResult.ok()) {
            utils::GetLogger().Error("Failed to read key file: " + keyPath + ", error: " + dataResult.error().message);
            continue;
        }
        
        auto keyInfoResult = keyInfoFromPEM(dataResult.value(), keyPath);
        if (!keyInfoResult.ok()) {
            utils::GetLogger().Error("Failed to parse key info from: " + keyPath + ", error: " + keyInfoResult.error().message);
            continue;
        }
        
        auto [keyID, keyInfo] = keyInfoResult.value();
        keyInfoMap[keyID] = keyInfo;
    }
    
    return keyInfoMap;
}

Result<std::tuple<std::string, KeyInfo>> GenericKeyStore::keyInfoFromPEM(
    const std::vector<uint8_t>& pemBytes, 
    const std::string& filename) {
    
    // 从文件名提取keyID（去掉扩展名）
    std::filesystem::path path(filename);
    std::string keyID = path.stem().string();
    
    // 使用extractPrivateKeyAttributes从PEM内容中提取role和gun信息
    auto [role, gun, err] = utils::extractPrivateKeyAttributes(pemBytes, false);
    if (err.hasError()) {
        // 如果解析失败，使用默认值
        role = RoleName::TargetsRole;
        gun = "";
    }
    
    KeyInfo keyInfo(role, gun);
    return Result<std::tuple<std::string, KeyInfo>>(std::make_tuple(keyID, keyInfo));
}

Error GenericKeyStore::AddKey(const KeyInfo& keyInfo, std::shared_ptr<crypto::PrivateKey> privKey) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 根据Go语言逻辑：如果是root角色或delegation角色，清空gun
    KeyInfo adjustedKeyInfo = keyInfo;
    if (adjustedKeyInfo.role == RoleName::RootRole) {
        adjustedKeyInfo.gun = "";
    }
    
    std::string keyID = privKey->ID();
    
    // 获取密码
    std::string chosenPassphrase;
    bool giveup = false;
    Error err;
    
    for (int attempts = 0; ; attempts++) {
        std::tie(chosenPassphrase, giveup, err) = passRetriever_(
            keyID, 
            roleToString(adjustedKeyInfo.role), 
            true, 
            attempts
        );
        
        if (!err.hasError()) {
            break;
        }
        
        if (giveup || attempts > 10) {
            return Error("Password attempts exceeded");
        }
    }
    
    // 将私钥转换为PKCS8格式（这是唯一需要的转换）
    std::string pemPrivKeyStr;
    try {
        pemPrivKeyStr = utils::ConvertPrivateKeyToPKCS8(
            privKey, 
            roleToString(adjustedKeyInfo.role), 
            adjustedKeyInfo.gun, 
            chosenPassphrase
        );
    } catch (const std::exception& e) {
        return Error("Failed to convert private key to PKCS8: " + std::string(e.what()));
    }
    
    std::vector<uint8_t> pemPrivKey(pemPrivKeyStr.begin(), pemPrivKeyStr.end());
    
    // 缓存密钥
    cachedKeys_[keyID] = std::make_unique<CachedKey>(adjustedKeyInfo.role, privKey);
    
    // 保存到存储
    auto saveErr = store_->Set(keyID, pemPrivKey);
    if (saveErr.hasError()) {
        return saveErr;
    }
    
    // 更新密钥信息映射
    keyInfoMap_[keyID] = adjustedKeyInfo;
    
    return Error(); // 成功
}

Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>> GenericKeyStore::GetKey(const std::string& keyID) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 检查缓存
    auto cachedIt = cachedKeys_.find(keyID);
    if (cachedIt != cachedKeys_.end()) {
        return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>>(
            std::make_tuple(cachedIt->second->key, cachedIt->second->role)
        );
    }
    
    // 从存储获取角色信息
    auto roleResult = getKeyRole(keyID);
    if (!roleResult.ok()) {
        return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>>(roleResult.error());
    }
    RoleName role = roleResult.value();
    
    // 从存储获取密钥内容
    auto keyBytesResult = store_->Get(keyID);
    if (!keyBytesResult.ok()) {
        return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>>(keyBytesResult.error());
    }
    auto keyBytes = keyBytesResult.value();
    
    // 首先尝试无密码解析PEM私钥（与Go语言逻辑一致）
    auto parseResult = utils::ParsePEMPrivateKey(keyBytes, "");
    if (parseResult.ok()) {
        // 解析成功，将密钥添加到缓存并返回
        auto privKey = parseResult.value();
        cachedKeys_[keyID] = std::make_unique<CachedKey>(role, privKey);
        return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>>(
            std::make_tuple(privKey, role)
        );
    }
    
    // 如果无密码解析失败，则尝试使用密码解密
    auto decryptResult = getPasswdDecryptBytes(keyBytes, keyID, roleToString(role));
    if (!decryptResult.ok()) {
        return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>>(decryptResult.error());
    }
    
    auto [privKey, passwd] = decryptResult.value();
    
    // 缓存密钥
    cachedKeys_[keyID] = std::make_unique<CachedKey>(role, privKey);
    
    return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>>(
        std::make_tuple(privKey, role)
    );
}

Result<KeyInfo> GenericKeyStore::GetKeyInfo(const std::string& keyID) {
    auto it = keyInfoMap_.find(keyID);
    if (it == keyInfoMap_.end()) {
        return Result<KeyInfo>(Error("Could not find info for keyID: " + keyID));
    }
    return Result<KeyInfo>(it->second);
}

std::map<std::string, KeyInfo> GenericKeyStore::ListKeys() {
    return keyInfoMap_;
}

Error GenericKeyStore::RemoveKey(const std::string& keyID) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 从缓存中删除
    cachedKeys_.erase(keyID);
    
    // 从存储中删除
    auto err = store_->Remove(keyID);
    if (err.hasError()) {
        return err;
    }
    
    // 从密钥信息映射中删除
    keyInfoMap_.erase(keyID);
    
    return Error(); // 成功
}

std::string GenericKeyStore::Name() const {
    return store_->Location();
}

Result<RoleName> GenericKeyStore::getKeyRole(const std::string& keyID) {
    // 首先尝试从keyInfoMap获取
    auto it = keyInfoMap_.find(keyID);
    if (it != keyInfoMap_.end()) {
        return Result<RoleName>(it->second.role);
    }
    
    // 遍历存储中的文件
    for (const auto& file : store_->ListFiles()) {
        std::filesystem::path path(file);
        std::string filename = path.stem().string();
        
        if (filename == keyID || file.find(keyID) == 0) {
            auto dataResult = store_->Get(file);
            if (!dataResult.ok()) {
                continue;
            }
            
            auto keyInfoResult = keyInfoFromPEM(dataResult.value(), file);
            if (!keyInfoResult.ok()) {
                continue;
            }
            
            auto [foundKeyID, keyInfo] = keyInfoResult.value();
            return Result<RoleName>(keyInfo.role);
        }
    }
    
    return Result<RoleName>(Error("Key not found: " + keyID));
}

Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, std::string>> GenericKeyStore::getPasswdDecryptBytes(
    const std::vector<uint8_t>& pemBytes,
    const std::string& name,
    const std::string& alias) {
    
    std::string passwd;
    std::shared_ptr<crypto::PrivateKey> privKey;
    
    for (int attempts = 0; ; attempts++) {
        bool giveup;
        Error err;
        
        // Notary 允许用户最多尝试 10 次输入密码
        if (attempts > 10) {
            return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, std::string>>(
                Error("Password attempts exceeded")
            );
        }
        
        std::tie(passwd, giveup, err) = passRetriever_(name, alias, false, attempts);
        
        // 检查是否终止输入或错误
        if (giveup || err.hasError()) {
            return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, std::string>>(
                Error("Password invalid or retrieval failed")
            );
        }
        
        // 尝试用密码解密 PEM 并解析私钥
        auto parseResult = utils::ParsePEMPrivateKey(pemBytes, passwd);
        if (parseResult.ok()) {
            // 解析成功，退出循环
            privKey = parseResult.value();
            break;
        }
        
        // 解析失败，继续下一次尝试
    }
    
    return Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, std::string>>(
        std::make_tuple(privKey, passwd)
    );
}

// 工厂函数实现
std::unique_ptr<GenericKeyStore> NewKeyFileStore(
    const std::string& baseDir, 
    PassRetriever passRetriever) {
    return GenericKeyStore::NewKeyFileStore(baseDir, passRetriever);
}

std::unique_ptr<GenericKeyStore> NewKeyMemoryStore(
    PassRetriever passRetriever) {
    return GenericKeyStore::NewKeyMemoryStore(passRetriever);
}

} // namespace storage
} // namespace notary