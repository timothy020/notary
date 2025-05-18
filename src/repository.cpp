#include "notary/repository.hpp"
#include <algorithm>
#include <nlohmann/json.hpp>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace notary {

using json = nlohmann::json;

namespace {
// 检查角色是否可以由服务器管理
bool isValidServerManagedRole(RoleName role) {
    return role == RoleName::TimestampRole || role == RoleName::SnapshotRole;
}

// 检查角色是否是根角色
bool isRootRole(RoleName role) {
    return role == RoleName::RootRole;
}

// 检查角色是否是目标角色
bool isTargetsRole(RoleName role) {
    return role == RoleName::TargetsRole;
}

// 获取角色的默认过期时间
std::chrono::system_clock::time_point getDefaultExpiry(RoleName role) {
    auto now = std::chrono::system_clock::now();
    switch (role) {
        case RoleName::RootRole:
            return now + std::chrono::hours(24 * 365 * 10); // 10年
        case RoleName::TargetsRole:
        case RoleName::SnapshotRole:
            return now + std::chrono::hours(24 * 365 * 3);  // 3年
        case RoleName::TimestampRole:
            return now + std::chrono::hours(24 * 14);       // 14天
        default:
            return now + std::chrono::hours(24 * 365);      // 1年
    }
}

// 获取角色的类型字符串
std::string getRoleType(RoleName role) {
    switch (role) {
        case RoleName::RootRole:
            return "Root";
        case RoleName::TargetsRole:
            return "Targets";
        case RoleName::SnapshotRole:
            return "Snapshot";
        case RoleName::TimestampRole:
            return "Timestamp";
        default:
            return "Unknown";
    }
}

// 计算文件的哈希值
json calculateHashes(const std::string& data) {
    json hashes;
    
    // 计算SHA-256哈希
    unsigned char hash_sha256[EVP_MAX_MD_SIZE];
    unsigned int hash_sha256_len;
    EVP_MD_CTX* mdctx_sha256 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx_sha256, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx_sha256, data.c_str(), data.length());
    EVP_DigestFinal_ex(mdctx_sha256, hash_sha256, &hash_sha256_len);
    EVP_MD_CTX_free(mdctx_sha256);
    
    // Base64编码SHA-256哈希
    BIO* b64_sha256 = BIO_new(BIO_f_base64());
    BIO* mem_sha256 = BIO_new(BIO_s_mem());
    BIO_push(b64_sha256, mem_sha256);
    BIO_write(b64_sha256, hash_sha256, hash_sha256_len);
    BIO_flush(b64_sha256);
    
    BUF_MEM* bptr_sha256;
    BIO_get_mem_ptr(b64_sha256, &bptr_sha256);
    std::string sha256_base64(bptr_sha256->data, bptr_sha256->length);
    // 移除换行符
    sha256_base64.erase(std::remove(sha256_base64.begin(), sha256_base64.end(), '\n'), sha256_base64.end());
    
    // 计算SHA-512哈希
    unsigned char hash_sha512[EVP_MAX_MD_SIZE];
    unsigned int hash_sha512_len;
    EVP_MD_CTX* mdctx_sha512 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx_sha512, EVP_sha512(), nullptr);
    EVP_DigestUpdate(mdctx_sha512, data.c_str(), data.length());
    EVP_DigestFinal_ex(mdctx_sha512, hash_sha512, &hash_sha512_len);
    EVP_MD_CTX_free(mdctx_sha512);
    
    // Base64编码SHA-512哈希
    BIO* b64_sha512 = BIO_new(BIO_f_base64());
    BIO* mem_sha512 = BIO_new(BIO_s_mem());
    BIO_push(b64_sha512, mem_sha512);
    BIO_write(b64_sha512, hash_sha512, hash_sha512_len);
    BIO_flush(b64_sha512);
    
    BUF_MEM* bptr_sha512;
    BIO_get_mem_ptr(b64_sha512, &bptr_sha512);
    std::string sha512_base64(bptr_sha512->data, bptr_sha512->length);
    // 移除换行符
    sha512_base64.erase(std::remove(sha512_base64.begin(), sha512_base64.end(), '\n'), sha512_base64.end());
    
    // 释放资源
    BIO_free_all(b64_sha256);
    BIO_free_all(b64_sha512);
    
    hashes["sha256"] = sha256_base64;
    hashes["sha512"] = sha512_base64;
    
    return hashes;
}

// 创建文件元数据
json createFileMeta(const json& data) {
    json meta;
    std::string dataStr = data.dump();
    meta["length"] = dataStr.size();
    meta["hashes"] = calculateHashes(dataStr);
    return meta;
}

// 将crypto::PublicKey转换为notary::PublicKey的适配器类
class PublicKeyAdapter : public PublicKey {
public:
    explicit PublicKeyAdapter(std::shared_ptr<crypto::PublicKey> key) 
        : key_(key) {}
    
    std::string ID() const override {
        return key_->ID();
    }
    
    KeyAlgorithm Algorithm() const override {
        return KeyAlgorithm::ECDSA; // 暂时默认为ECDSA
    }
    
    std::vector<uint8_t> Bytes() const override {
        // 获取正确的公钥数据
        auto ecdsaKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(key_);
        if (ecdsaKey) {
            return ecdsaKey->GetDERData();
        }
        return {}; // 如果不是ECDSA密钥，返回空
    }
    
private:
    std::shared_ptr<crypto::PublicKey> key_;
};

// 将crypto::PublicKey转换为notary::PublicKey
std::shared_ptr<PublicKey> adaptPublicKey(const std::shared_ptr<crypto::PublicKey>& key) {
    return std::make_shared<PublicKeyAdapter>(key);
}

// 实现base64编码函数
std::string base64Encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    
    // 移除可能存在的换行符
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
    
    BIO_free_all(b64);
    return result;
}

} // namespace

Repository::Repository(const std::string& trustDir, const std::string& serverURL)
    : baseURL_(serverURL)
    , cache_(trustDir)
    , remoteStore_(serverURL) {
}

void Repository::SetPassphrase(const std::string& passphrase) {
    cryptoService_.SetDefaultPassphrase(passphrase);
}

std::shared_ptr<PublicKey> Repository::CreatePublicKey(const std::vector<uint8_t>& keyBytes, 
                                                      const std::string& keyType) {
    KeyAlgorithm algorithm;
    if (keyType == "ecdsa") {
        algorithm = KeyAlgorithm::ECDSA;
    } else if (keyType == "rsa") {
        algorithm = KeyAlgorithm::RSA;
    } else if (keyType == "ed25519") {
        algorithm = KeyAlgorithm::ED25519;
    } else {
        return nullptr;
    }
    
    // 为远程密钥创建一个临时角色
    auto result = cryptoService_.Create(RoleName::TimestampRole, gun_, algorithm);
    if (!result.ok()) {
        return nullptr;
    }
    return adaptPublicKey(result.value());
}

Error Repository::Initialize(const std::vector<std::string>& rootKeyIDs,
                           const std::vector<RoleName>& serverManagedRoles) {
    // 验证服务器管理的角色
    std::vector<RoleName> remoteRoles = {RoleName::TimestampRole}; // timestamp总是由服务器管理
    std::vector<RoleName> localRoles = {RoleName::TargetsRole, RoleName::SnapshotRole};

    for (const auto& role : serverManagedRoles) {
        if (!isValidServerManagedRole(role)) {
            return Error("Invalid server managed role");
        }
        if (role == RoleName::SnapshotRole) {
            // 将snapshot从本地管理移到远程管理
            localRoles.erase(
                std::remove(localRoles.begin(), localRoles.end(), RoleName::SnapshotRole),
                localRoles.end()
            );
            remoteRoles.push_back(role);
        }
    }

    // 获取或创建根密钥
    std::vector<std::shared_ptr<PublicKey>> rootKeys;
    
    // 如果提供了根密钥ID，使用这些ID获取密钥
    if (!rootKeyIDs.empty()) {
        for (const auto& keyID : rootKeyIDs) {
            auto key = cryptoService_.GetKey(keyID);
            if (!key.ok()) {
                return Error("Root key not found: " + keyID);
            }
            rootKeys.push_back(adaptPublicKey(key.value()));
        }
    } else {
        // 如果没有提供根密钥ID，自动创建一个新的根密钥
        auto keyResult = cryptoService_.Create(RoleName::RootRole, gun_, KeyAlgorithm::ECDSA);
        if (!keyResult.ok()) {
            return Error("Failed to create root key: " + keyResult.error().what());
        }
        rootKeys.push_back(adaptPublicKey(keyResult.value()));
    }
    
    // 确保至少有一个根密钥
    if (rootKeys.empty()) {
        return Error("No root keys available");
    }

    // 初始化角色
    auto [root, targets, snapshot, timestamp] = initializeRoles(rootKeys, localRoles, remoteRoles);

    // 初始化TUF元数据
    return initializeTUFMetadata(root, targets, snapshot, timestamp);
}

std::tuple<BaseRole, BaseRole, BaseRole, BaseRole> 
Repository::initializeRoles(const std::vector<std::shared_ptr<PublicKey>>& rootKeys,
                          const std::vector<RoleName>& localRoles,
                          const std::vector<RoleName>& remoteRoles) {
    // 创建根角色
    BaseRole root(RoleName::RootRole, 1, rootKeys);
    
    // 初始化其他角色的空密钥列表
    std::vector<std::shared_ptr<PublicKey>> emptyKeys;
    BaseRole targets(RoleName::TargetsRole, 0, emptyKeys);
    BaseRole snapshot(RoleName::SnapshotRole, 0, emptyKeys);
    BaseRole timestamp(RoleName::TimestampRole, 0, emptyKeys);

    // 创建本地角色密钥
    for (const auto& role : localRoles) {
        auto keyResult = cryptoService_.Create(role, gun_, KeyAlgorithm::ECDSA);
        if (!keyResult.ok()) {
            continue; // 跳过失败的密钥创建
        }
        auto key = adaptPublicKey(keyResult.value());
        std::vector<std::shared_ptr<PublicKey>> roleKeys = {key};
        
        if (role == RoleName::TargetsRole) {
            targets = BaseRole(role, 1, roleKeys);
        } else if (role == RoleName::SnapshotRole) {
            snapshot = BaseRole(role, 1, roleKeys);
        }
    }

    // 获取远程角色密钥
    for (const auto& role : remoteRoles) {
        auto keyResult = remoteStore_.GetRemote(gun_.empty() ? "default" : gun_, 
                                              role == RoleName::TimestampRole ? "timestamp" : "snapshot");
        if (!keyResult.ok()) {
            continue; // 跳过失败的密钥获取
        }
        
        // 从json中提取公钥信息并创建公钥对象
        auto key = keyResult.value()["public_key"];
        std::vector<uint8_t> keyBytes = key["public"];
        std::string keyType = key["type"];
        
        // 创建公钥对象
        auto publicKey = CreatePublicKey(keyBytes, keyType);
        if (publicKey) {
            std::vector<std::shared_ptr<PublicKey>> roleKeys = {publicKey};
            
            if (role == RoleName::TimestampRole) {
                timestamp = BaseRole(role, 1, roleKeys);
            } else if (role == RoleName::SnapshotRole) {
                snapshot = BaseRole(role, 1, roleKeys);
            }
        }
    }

    return {root, targets, snapshot, timestamp};
}

Error Repository::initializeTUFMetadata(const BaseRole& root,
                                     const BaseRole& targets,
                                     const BaseRole& snapshot,
                                     const BaseRole& timestamp) {
    try {
        // 创建标准的TUF格式，包含signed和signatures部分
        json rootJsonSigned;
        rootJsonSigned["_type"] = getRoleType(RoleName::RootRole);
        rootJsonSigned["consistent_snapshot"] = false;
        rootJsonSigned["version"] = 1;
        
        // 使用ISO 8601格式的过期时间
        auto expiry = getDefaultExpiry(RoleName::RootRole);
        auto expTime = std::chrono::system_clock::to_time_t(expiry);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&expTime), "%Y-%m-%dT%H:%M:%S%z");
        rootJsonSigned["expires"] = ss.str();
        
        // 添加所有角色的密钥信息
        json keys;
        if (!root.Keys().empty()) {
            for (const auto& key : root.Keys()) {
                std::string keyID = key->ID();
                json keyInfo;
                keyInfo["keytype"] = "ecdsa"; // 假设使用ECDSA
                
                // 密钥值
                json keyval;
                keyval["private"] = nullptr; // 私钥为null
                
                // 提取公钥DER数据并进行base64编码
                auto publicKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(key);
                if (publicKey && !publicKey->GetDERData().empty()) {
                    keyval["public"] = base64Encode(publicKey->GetDERData());
                } else {
                    // 尝试通过适配器接口获取公钥数据
                    std::vector<uint8_t> keyBytes = key->Bytes();
                    if (!keyBytes.empty()) {
                        keyval["public"] = base64Encode(keyBytes);
                    } else {
                        keyval["public"] = "";
                        std::cerr << "Warning: Empty public key for key ID " << keyID << " in root role" << std::endl;
                    }
                }
                
                keyInfo["keyval"] = keyval;
                keys[keyID] = keyInfo;
            }
        }
        
        // 修改targets密钥的处理部分
        for (const auto& key : targets.Keys()) {
            std::string keyID = key->ID();
            json keyInfo;
            keyInfo["keytype"] = "ecdsa";
            json keyval;
            keyval["private"] = nullptr;
            
            // 提取公钥DER数据并base64编码
            auto publicKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(key);
            if (publicKey && !publicKey->GetDERData().empty()) {
                keyval["public"] = base64Encode(publicKey->GetDERData());
            } else {
                // 尝试通过适配器接口获取公钥数据
                auto adaptedKey = adaptPublicKey(std::dynamic_pointer_cast<crypto::PublicKey>(key));
                std::vector<uint8_t> keyBytes = adaptedKey->Bytes();
                if (!keyBytes.empty()) {
                    keyval["public"] = base64Encode(keyBytes);
                } else {
                    // 尝试通过密钥管理器获取公钥
                    auto storedKeyResult = cryptoService_.GetKey(keyID);
                    if (storedKeyResult.ok()) {
                        auto storedECDSAKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(storedKeyResult.value());
                        if (storedECDSAKey && !storedECDSAKey->GetDERData().empty()) {
                            keyval["public"] = base64Encode(storedECDSAKey->GetDERData());
                        } else {
                            keyval["public"] = "";
                            std::cerr << "Warning: Empty public key for key ID " << keyID << " in targets role" << std::endl;
                        }
                    } else {
                        keyval["public"] = "";
                        std::cerr << "Warning: Could not get public key for ID " << keyID << " in targets role: " 
                                 << storedKeyResult.error().what() << std::endl;
                    }
                }
            }
            
            keyInfo["keyval"] = keyval;
            keys[keyID] = keyInfo;
        }
        
        // 修改snapshot密钥的处理部分
        for (const auto& key : snapshot.Keys()) {
            std::string keyID = key->ID();
            json keyInfo;
            keyInfo["keytype"] = "ecdsa";
            json keyval;
            keyval["private"] = nullptr;
            
            // 提取公钥DER数据并base64编码
            auto publicKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(key);
            if (publicKey && !publicKey->GetDERData().empty()) {
                keyval["public"] = base64Encode(publicKey->GetDERData());
            } else {
                // 尝试通过适配器接口获取公钥数据
                auto adaptedKey = adaptPublicKey(std::dynamic_pointer_cast<crypto::PublicKey>(key));
                std::vector<uint8_t> keyBytes = adaptedKey->Bytes();
                if (!keyBytes.empty()) {
                    keyval["public"] = base64Encode(keyBytes);
                } else {
                    // 尝试通过密钥管理器获取公钥
                    auto storedKeyResult = cryptoService_.GetKey(keyID);
                    if (storedKeyResult.ok()) {
                        auto storedECDSAKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(storedKeyResult.value());
                        if (storedECDSAKey && !storedECDSAKey->GetDERData().empty()) {
                            keyval["public"] = base64Encode(storedECDSAKey->GetDERData());
                        } else {
                            keyval["public"] = "";
                            std::cerr << "Warning: Empty public key for key ID " << keyID << " in snapshot role" << std::endl;
                        }
                    } else {
                        keyval["public"] = "";
                        std::cerr << "Warning: Could not get public key for ID " << keyID << " in snapshot role: " 
                                 << storedKeyResult.error().what() << std::endl;
                    }
                }
            }
            
            keyInfo["keyval"] = keyval;
            keys[keyID] = keyInfo;
        }
        
        // 修改timestamp密钥的处理部分
        for (const auto& key : timestamp.Keys()) {
            std::string keyID = key->ID();
            json keyInfo;
            keyInfo["keytype"] = "ecdsa";
            json keyval;
            keyval["private"] = nullptr;
            
            // 提取公钥DER数据并base64编码
            auto publicKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(key);
            if (publicKey && !publicKey->GetDERData().empty()) {
                keyval["public"] = base64Encode(publicKey->GetDERData());
            } else {
                // 尝试通过适配器接口获取公钥数据
                auto adaptedKey = adaptPublicKey(std::dynamic_pointer_cast<crypto::PublicKey>(key));
                std::vector<uint8_t> keyBytes = adaptedKey->Bytes();
                if (!keyBytes.empty()) {
                    keyval["public"] = base64Encode(keyBytes);
                } else {
                    // 尝试通过密钥管理器获取公钥
                    auto storedKeyResult = cryptoService_.GetKey(keyID);
                    if (storedKeyResult.ok()) {
                        auto storedECDSAKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(storedKeyResult.value());
                        if (storedECDSAKey && !storedECDSAKey->GetDERData().empty()) {
                            keyval["public"] = base64Encode(storedECDSAKey->GetDERData());
                        } else {
                            keyval["public"] = "";
                            std::cerr << "Warning: Empty public key for key ID " << keyID << " in timestamp role" << std::endl;
                        }
                    } else {
                        keyval["public"] = "";
                        std::cerr << "Warning: Could not get public key for ID " << keyID << " in timestamp role: " 
                                 << storedKeyResult.error().what() << std::endl;
                    }
                }
            }
            
            keyInfo["keyval"] = keyval;
            keys[keyID] = keyInfo;
        }
        
        rootJsonSigned["keys"] = keys;
        
        // 添加角色信息
        json roles;
        if (!root.Keys().empty()) {
            roles["root"] = {
                {"keyids", {root.Keys()[0]->ID()}},
                {"threshold", root.Threshold()}
            };
        } else {
            roles["root"] = {
                {"keyids", json::array()},
                {"threshold", root.Threshold()}
            };
        }
        
        if (!targets.Keys().empty()) {
            roles["targets"] = {
                {"keyids", {targets.Keys()[0]->ID()}},
                {"threshold", targets.Threshold()}
            };
        } else {
            roles["targets"] = {
                {"keyids", json::array()},
                {"threshold", targets.Threshold()}
            };
        }
        
        if (!snapshot.Keys().empty()) {
            roles["snapshot"] = {
                {"keyids", {snapshot.Keys()[0]->ID()}},
                {"threshold", snapshot.Threshold()}
            };
        } else {
            roles["snapshot"] = {
                {"keyids", json::array()},
                {"threshold", snapshot.Threshold()}
            };
        }
        
        if (!timestamp.Keys().empty()) {
            roles["timestamp"] = {
                {"keyids", {timestamp.Keys()[0]->ID()}},
                {"threshold", timestamp.Threshold()}
            };
        } else {
            roles["timestamp"] = {
                {"keyids", json::array()},
                {"threshold", timestamp.Threshold()}
            };
        }
        
        rootJsonSigned["roles"] = roles;
        
        // 签名元数据文件
        json rootSig = json::array();
        if (!root.Keys().empty()) {
            auto rootKeyID = root.Keys()[0]->ID();
            auto privKeyResult = cryptoService_.GetPrivateKey(rootKeyID);
            if (privKeyResult.ok()) {
                // 创建签名
                std::string canonicalRoot = rootJsonSigned.dump();
                
                // 计算数据的SHA-256哈希
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int hashLen;
                EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                if (mdctx == nullptr) {
                    return Error("Failed to create MD context");
                }
                
                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to initialize digest");
                }
                
                if (EVP_DigestUpdate(mdctx, canonicalRoot.c_str(), canonicalRoot.length()) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to update digest");
                }
                
                if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to finalize digest");
                }
                
                EVP_MD_CTX_free(mdctx);
                
                // 使用私钥签名哈希
                auto ecdsaPrivKey = std::dynamic_pointer_cast<crypto::ECDSAPrivateKey>(privKeyResult.value());
                if (ecdsaPrivKey) {
                    // 将DER数据转换为EC_KEY
                    EC_KEY* ecKey = nullptr;
                    const unsigned char* p = ecdsaPrivKey->GetDERData().data();
                    ecKey = d2i_ECPrivateKey(nullptr, &p, ecdsaPrivKey->GetDERData().size());
                    
                    if (ecKey) {
                        // 创建签名上下文
                        ECDSA_SIG* signature = ECDSA_do_sign(hash, hashLen, ecKey);
                        if (signature) {
                            // 将签名序列化为DER格式
                            unsigned char* sig_bytes = nullptr;
                            int sig_len = i2d_ECDSA_SIG(signature, &sig_bytes);
                            
                            if (sig_len > 0 && sig_bytes) {
                                // Base64编码签名
                                BIO* b64 = BIO_new(BIO_f_base64());
                                BIO* mem = BIO_new(BIO_s_mem());
                                BIO_push(b64, mem);
                                BIO_write(b64, sig_bytes, sig_len);
                                BIO_flush(b64);
                                
                                BUF_MEM* bptr;
                                BIO_get_mem_ptr(b64, &bptr);
                                std::string b64sig(bptr->data, bptr->length);
                                
                                // 移除可能存在的换行符
                                b64sig.erase(std::remove(b64sig.begin(), b64sig.end(), '\n'), b64sig.end());
                                
                                // 添加签名到rootSig
                                json sigObj;
                                sigObj["keyid"] = rootKeyID;
                                sigObj["method"] = "ecdsa"; // 添加method字段
                                sigObj["sig"] = b64sig;
                                rootSig.push_back(sigObj);
                                
                                // 清理资源
                                BIO_free_all(b64);
                                OPENSSL_free(sig_bytes);
                            }
                            ECDSA_SIG_free(signature);
                        }
                        EC_KEY_free(ecKey);
                    }
                }
            }
        }
        
        // 创建最终的root.json，包含signed和signatures部分
        json rootJson;
        rootJson["signed"] = rootJsonSigned;
        rootJson["signatures"] = rootSig;
        
        // 创建和签名targets.json
        json targetsJsonSigned;
        targetsJsonSigned["_type"] = getRoleType(RoleName::TargetsRole);
        targetsJsonSigned["version"] = 1;
        
        // 使用ISO 8601格式的过期时间
        auto targetsExpiry = getDefaultExpiry(RoleName::TargetsRole);
        auto targetsExpTime = std::chrono::system_clock::to_time_t(targetsExpiry);
        std::stringstream tsss;
        tsss << std::put_time(std::localtime(&targetsExpTime), "%Y-%m-%dT%H:%M:%S%z");
        targetsJsonSigned["expires"] = tsss.str();
        
        targetsJsonSigned["targets"] = json::object();
        
        // 添加delegations字段，与Go版本兼容
        json delegations;
        delegations["keys"] = json::object();
        delegations["roles"] = json::array();
        targetsJsonSigned["delegations"] = delegations;
        
        // 签名targets元数据
        json targetsSig = json::array();
        if (!targets.Keys().empty()) {
            auto targetKeyID = targets.Keys()[0]->ID();
            auto privKeyResult = cryptoService_.GetPrivateKey(targetKeyID);
            if (privKeyResult.ok()) {
                // 创建签名
                std::string canonicalTargets = targetsJsonSigned.dump();
                
                // 计算数据的SHA-256哈希
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int hashLen;
                EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                if (mdctx == nullptr) {
                    return Error("Failed to create MD context");
                }
                
                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to initialize digest");
                }
                
                if (EVP_DigestUpdate(mdctx, canonicalTargets.c_str(), canonicalTargets.length()) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to update digest");
                }
                
                if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to finalize digest");
                }
                
                EVP_MD_CTX_free(mdctx);
                
                // 使用私钥签名哈希
                auto ecdsaPrivKey = std::dynamic_pointer_cast<crypto::ECDSAPrivateKey>(privKeyResult.value());
                if (ecdsaPrivKey) {
                    // 将DER数据转换为EC_KEY
                    EC_KEY* ecKey = nullptr;
                    const unsigned char* p = ecdsaPrivKey->GetDERData().data();
                    ecKey = d2i_ECPrivateKey(nullptr, &p, ecdsaPrivKey->GetDERData().size());
                    
                    if (ecKey) {
                        // 创建签名上下文
                        ECDSA_SIG* signature = ECDSA_do_sign(hash, hashLen, ecKey);
                        if (signature) {
                            // 将签名序列化为DER格式
                            unsigned char* sig_bytes = nullptr;
                            int sig_len = i2d_ECDSA_SIG(signature, &sig_bytes);
                            
                            if (sig_len > 0 && sig_bytes) {
                                // Base64编码签名
                                BIO* b64 = BIO_new(BIO_f_base64());
                                BIO* mem = BIO_new(BIO_s_mem());
                                BIO_push(b64, mem);
                                BIO_write(b64, sig_bytes, sig_len);
                                BIO_flush(b64);
                                
                                BUF_MEM* bptr;
                                BIO_get_mem_ptr(b64, &bptr);
                                std::string b64sig(bptr->data, bptr->length);
                                
                                // 移除可能存在的换行符
                                b64sig.erase(std::remove(b64sig.begin(), b64sig.end(), '\n'), b64sig.end());
                                
                                // 添加签名到targetsSig
                                json sigObj;
                                sigObj["keyid"] = targetKeyID;
                                sigObj["method"] = "ecdsa";
                                sigObj["sig"] = b64sig;
                                targetsSig.push_back(sigObj);
                                
                                // 清理资源
                                BIO_free_all(b64);
                                OPENSSL_free(sig_bytes);
                            }
                            ECDSA_SIG_free(signature);
                        }
                        EC_KEY_free(ecKey);
                    }
                }
            }
        }
        
        json targetsJson;
        targetsJson["signed"] = targetsJsonSigned;
        targetsJson["signatures"] = targetsSig;
        
        // 创建并签名snapshot.json
        json snapshotJsonSigned;
        snapshotJsonSigned["_type"] = getRoleType(RoleName::SnapshotRole);
        snapshotJsonSigned["version"] = 1;
        
        auto snapshotExpiry = getDefaultExpiry(RoleName::SnapshotRole);
        auto snapshotExpTime = std::chrono::system_clock::to_time_t(snapshotExpiry);
        std::stringstream ssss;
        ssss << std::put_time(std::localtime(&snapshotExpTime), "%Y-%m-%dT%H:%M:%S%z");
        snapshotJsonSigned["expires"] = ssss.str();
        
        // 添加root和targets的元数据
        json meta;
        meta["root.json"] = createFileMeta(rootJson);
        meta["targets.json"] = createFileMeta(targetsJson);
        snapshotJsonSigned["meta"] = meta;
        
        // 签名snapshot元数据
        json snapshotSig = json::array();
        if (!snapshot.Keys().empty()) {
            auto snapshotKeyID = snapshot.Keys()[0]->ID();
            auto privKeyResult = cryptoService_.GetPrivateKey(snapshotKeyID);
            if (privKeyResult.ok()) {
                // 创建签名
                std::string canonicalSnapshot = snapshotJsonSigned.dump();
                
                // 计算数据的SHA-256哈希
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int hashLen;
                EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                if (mdctx == nullptr) {
                    return Error("Failed to create MD context");
                }
                
                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to initialize digest");
                }
                
                if (EVP_DigestUpdate(mdctx, canonicalSnapshot.c_str(), canonicalSnapshot.length()) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to update digest");
                }
                
                if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to finalize digest");
                }
                
                EVP_MD_CTX_free(mdctx);
                
                // 使用私钥签名哈希
                auto ecdsaPrivKey = std::dynamic_pointer_cast<crypto::ECDSAPrivateKey>(privKeyResult.value());
                if (ecdsaPrivKey) {
                    // 将DER数据转换为EC_KEY
                    EC_KEY* ecKey = nullptr;
                    const unsigned char* p = ecdsaPrivKey->GetDERData().data();
                    ecKey = d2i_ECPrivateKey(nullptr, &p, ecdsaPrivKey->GetDERData().size());
                    
                    if (ecKey) {
                        // 创建签名上下文
                        ECDSA_SIG* signature = ECDSA_do_sign(hash, hashLen, ecKey);
                        if (signature) {
                            // 将签名序列化为DER格式
                            unsigned char* sig_bytes = nullptr;
                            int sig_len = i2d_ECDSA_SIG(signature, &sig_bytes);
                            
                            if (sig_len > 0 && sig_bytes) {
                                // Base64编码签名
                                BIO* b64 = BIO_new(BIO_f_base64());
                                BIO* mem = BIO_new(BIO_s_mem());
                                BIO_push(b64, mem);
                                BIO_write(b64, sig_bytes, sig_len);
                                BIO_flush(b64);
                                
                                BUF_MEM* bptr;
                                BIO_get_mem_ptr(b64, &bptr);
                                std::string b64sig(bptr->data, bptr->length);
                                
                                // 移除可能存在的换行符
                                b64sig.erase(std::remove(b64sig.begin(), b64sig.end(), '\n'), b64sig.end());
                                
                                // 添加签名到snapshotSig
                                json sigObj;
                                sigObj["keyid"] = snapshotKeyID;
                                sigObj["method"] = "ecdsa";
                                sigObj["sig"] = b64sig;
                                snapshotSig.push_back(sigObj);
                                
                                // 清理资源
                                BIO_free_all(b64);
                                OPENSSL_free(sig_bytes);
                            }
                            ECDSA_SIG_free(signature);
                        }
                        EC_KEY_free(ecKey);
                    }
                }
            }
        }
        
        json snapshotJson;
        snapshotJson["signed"] = snapshotJsonSigned;
        snapshotJson["signatures"] = snapshotSig;
        
        // 创建并签名timestamp.json
        json timestampJsonSigned;
        timestampJsonSigned["_type"] = getRoleType(RoleName::TimestampRole);
        timestampJsonSigned["version"] = 1;
        
        auto timestampExpiry = getDefaultExpiry(RoleName::TimestampRole);
        auto timestampExpTime = std::chrono::system_clock::to_time_t(timestampExpiry);
        std::stringstream tmss;
        tmss << std::put_time(std::localtime(&timestampExpTime), "%Y-%m-%dT%H:%M:%S%z");
        timestampJsonSigned["expires"] = tmss.str();
        
        // 添加snapshot的元数据
        json timestampMeta;
        timestampMeta["snapshot.json"] = createFileMeta(snapshotJson);
        timestampJsonSigned["meta"] = timestampMeta;
        
        // 签名timestamp元数据
        json timestampSig = json::array();
        if (!timestamp.Keys().empty()) {
            auto timestampKeyID = timestamp.Keys()[0]->ID();
            auto privKeyResult = cryptoService_.GetPrivateKey(timestampKeyID);
            if (privKeyResult.ok()) {
                // 创建签名
                std::string canonicalTimestamp = timestampJsonSigned.dump();
                
                // 计算数据的SHA-256哈希
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int hashLen;
                EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                if (mdctx == nullptr) {
                    return Error("Failed to create MD context");
                }
                
                if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to initialize digest");
                }
                
                if (EVP_DigestUpdate(mdctx, canonicalTimestamp.c_str(), canonicalTimestamp.length()) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to update digest");
                }
                
                if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
                    EVP_MD_CTX_free(mdctx);
                    return Error("Failed to finalize digest");
                }
                
                EVP_MD_CTX_free(mdctx);
                
                // 使用私钥签名哈希
                auto ecdsaPrivKey = std::dynamic_pointer_cast<crypto::ECDSAPrivateKey>(privKeyResult.value());
                if (ecdsaPrivKey) {
                    // 将DER数据转换为EC_KEY
                    EC_KEY* ecKey = nullptr;
                    const unsigned char* p = ecdsaPrivKey->GetDERData().data();
                    ecKey = d2i_ECPrivateKey(nullptr, &p, ecdsaPrivKey->GetDERData().size());
                    
                    if (ecKey) {
                        // 创建签名上下文
                        ECDSA_SIG* signature = ECDSA_do_sign(hash, hashLen, ecKey);
                        if (signature) {
                            // 将签名序列化为DER格式
                            unsigned char* sig_bytes = nullptr;
                            int sig_len = i2d_ECDSA_SIG(signature, &sig_bytes);
                            
                            if (sig_len > 0 && sig_bytes) {
                                // Base64编码签名
                                BIO* b64 = BIO_new(BIO_f_base64());
                                BIO* mem = BIO_new(BIO_s_mem());
                                BIO_push(b64, mem);
                                BIO_write(b64, sig_bytes, sig_len);
                                BIO_flush(b64);
                                
                                BUF_MEM* bptr;
                                BIO_get_mem_ptr(b64, &bptr);
                                std::string b64sig(bptr->data, bptr->length);
                                
                                // 移除可能存在的换行符
                                b64sig.erase(std::remove(b64sig.begin(), b64sig.end(), '\n'), b64sig.end());
                                
                                // 添加签名到timestampSig
                                json sigObj;
                                sigObj["keyid"] = timestampKeyID;
                                sigObj["method"] = "ecdsa";
                                sigObj["sig"] = b64sig;
                                timestampSig.push_back(sigObj);
                                
                                // 清理资源
                                BIO_free_all(b64);
                                OPENSSL_free(sig_bytes);
                            }
                            ECDSA_SIG_free(signature);
                        }
                        EC_KEY_free(ecKey);
                    }
                }
            }
        }
        
        json timestampJson;
        timestampJson["signed"] = timestampJsonSigned;
        timestampJson["signatures"] = timestampSig;
        
        // 保存所有元数据文件
        std::string gunStr = gun_.empty() ? "default" : gun_;
        cache_.Set(gunStr, "root.json", rootJson);
        cache_.Set(gunStr, "targets.json", targetsJson);
        cache_.Set(gunStr, "snapshot.json", snapshotJson);
        cache_.Set(gunStr, "timestamp.json", timestampJson);
        
        return Error();
    } catch (const std::exception& e) {
        return Error(std::string("Failed to initialize TUF metadata: ") + e.what());
    }
}

} // namespace notary 