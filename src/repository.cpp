#include "notary/repository.hpp"
#include "notary/tuf/repo.hpp"
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
#include <fstream>
#include <filesystem>
#include <ctime>
#include <uuid/uuid.h>
#include <iostream>

namespace notary {

using json = nlohmann::json;

// 使用标准filesystem命名空间
namespace fs = std::filesystem;

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

namespace changelist {

// Base64编码函数
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

// Base64解码函数
std::vector<uint8_t> base64Decode(const std::string& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(data.data(), data.size());
    BIO_push(b64, mem);
    
    std::vector<uint8_t> result(data.size());
    int decodedSize = BIO_read(b64, result.data(), data.size());
    if (decodedSize > 0) {
        result.resize(decodedSize);
    } else {
        result.clear();
    }
    
    BIO_free_all(b64);
    return result;
}

// FileChangelist实现
FileChangelist::FileChangelist(const std::string& dir) : dir_(dir) {
    // 确保目录存在
    try {
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to create changelist directory: " << e.what() << std::endl;
    }
}

std::vector<std::shared_ptr<Change>> FileChangelist::List() const {
    std::vector<std::shared_ptr<Change>> changes;
    
    try {
        // 获取目录下所有文件
        if (!fs::exists(dir_)) {
            return changes; // 目录不存在，返回空列表
        }
        
        std::vector<fs::directory_entry> files;
        for (const auto& entry : fs::directory_iterator(dir_)) {
            if (!fs::is_directory(entry.path())) {
                files.push_back(entry);
            }
        }
        
        // 按照文件名排序（文件名包含时间戳）
        std::sort(files.begin(), files.end(), 
                 [](const fs::directory_entry& a, const fs::directory_entry& b) {
                     return a.path().filename().string() < b.path().filename().string();
                 });
        
        // 读取并解析每个文件
        for (const auto& file : files) {
            std::ifstream fileStream(file.path(), std::ios::binary);
            if (!fileStream) {
                std::cerr << "Could not open file: " << file.path().string() << std::endl;
                continue;
            }
            
            // 读取文件内容
            json changeData;
            try {
                fileStream >> changeData;
                
                // 解析为TUFChange对象
                std::string action = changeData["action"];
                std::string role = changeData["role"];
                std::string type = changeData["type"];
                std::string path = changeData["path"];
                
                // 读取data字段 (而不是content)
                std::vector<uint8_t> content;
                if (changeData.contains("data") && !changeData["data"].is_null()) {
                    if (changeData["data"].is_string()) {
                        std::string dataStr = changeData["data"];
                        content = base64Decode(dataStr);
                    }
                }
                
                auto change = std::make_shared<TUFChange>(action, role, type, path, content);
                changes.push_back(change);
            } catch (const std::exception& e) {
                std::cerr << "Error parsing change file " << file.path().string() 
                          << ": " << e.what() << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error listing changes: " << e.what() << std::endl;
    }
    
    return changes;
}

Error FileChangelist::Add(const std::shared_ptr<Change>& change) {
    try {
        // 创建一个唯一的文件名，格式为：时间戳_UUID.change
        auto now = std::chrono::system_clock::now();
        auto nowNano = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();
        
        // 生成UUID
        uuid_t uuid;
        uuid_generate(uuid);
        char uuidStr[37]; // 36字符UUID + 结束符
        uuid_unparse(uuid, uuidStr);
        
        // 构建文件名
        std::stringstream ss;
        ss << std::setw(20) << std::setfill('0') << nowNano << "_" << uuidStr << ".change";
        std::string filename = ss.str();
        
        // 构建完整路径
        fs::path filePath = fs::path(dir_) / filename;
        
        // 创建JSON对象
        json changeData;
        changeData["action"] = change->Action();
        changeData["role"] = change->Scope();
        changeData["type"] = change->Type();
        changeData["path"] = change->Path();
        
        // 处理content字段，并以Base64编码存储为data字段
        const auto& content = change->Content();
        if (!content.empty()) {
            changeData["data"] = base64Encode(content);
        } else {
            changeData["data"] = nullptr;
        }
        
        // 写入文件
        std::ofstream fileStream(filePath, std::ios::binary);
        if (!fileStream) {
            return Error("Failed to create change file: " + filePath.string());
        }
        
        fileStream << changeData.dump(2); // 使用2空格缩进的格式输出JSON
        fileStream.close();
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add change: ") + e.what());
    }
}

Error FileChangelist::Clear(const std::string& archive) {
    try {
        // 如果目录不存在，直接返回
        if (!fs::exists(dir_)) {
            return Error("Changelist directory does not exist: " + dir_);
        }
        
        // 遍历目录中的所有文件并删除
        for (const auto& entry : fs::directory_iterator(dir_)) {
            if (!fs::is_directory(entry.path())) {
                fs::remove(entry.path());
            }
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to clear changelist: ") + e.what());
    }
}

Error FileChangelist::Close() {
    // 没有需要关闭的资源
    return Error();
}

} // namespace changelist

Repository::Repository(const std::string& trustDir, const std::string& serverURL)
    : trustDir_(trustDir)
    , serverURL_(serverURL)
    , cache_(std::make_shared<storage::MetadataStore>(trustDir))
    , remoteStore_(std::make_shared<storage::RemoteStore>(serverURL))
    , changelist_(std::make_shared<changelist::FileChangelist>(trustDir)) {
    
    // 初始化TUF Repo
    tufRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
    invalidRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
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

    // 创建本地角色密钥（不包括timestamp）
    for (const auto& role : localRoles) {
        if (role == RoleName::TimestampRole) {
            continue; // 跳过timestamp角色，它只从远程获取
        }
        
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
        auto keyResult = remoteStore_->GetKey(gun_.empty() ? "default" : gun_, 
                                          role == RoleName::TimestampRole ? "timestamp" : "snapshot");
        if (!keyResult.ok()) {
            std::cerr << "Failed to get remote key : " << keyResult.error().what() << std::endl;
            continue; // 跳过失败的密钥获取
        }
        
        // 从json中提取公钥信息
        auto keyJson = keyResult.value();
        std::cout << "远端获取到的keyJson: " << keyJson << std::endl;
        
        // 获取Base64编码的公钥数据
        std::string publicKeyB64 = keyJson["keyval"]["public"];
        
        // 解码Base64公钥数据
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new_mem_buf(publicKeyB64.data(), publicKeyB64.length());
        BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        
        std::vector<uint8_t> derData(publicKeyB64.size());
        int decodedSize = BIO_read(b64, derData.data(), publicKeyB64.size());
        if (decodedSize > 0) {
            derData.resize(decodedSize);
        } else {
            derData.clear();
        }
        BIO_free_all(b64);
        
        // 从DER数据创建ECDSA公钥
        const unsigned char* p = derData.data();
        EC_KEY* ecKey = d2i_EC_PUBKEY(nullptr, &p, derData.size());
        if (ecKey) {
            // 将EC_KEY转换为DER格式
            unsigned char* der = nullptr;
            int derLen = i2d_EC_PUBKEY(ecKey, &der);
            if (derLen > 0 && der) {
                std::vector<uint8_t> keyDer(der, der + derLen);
                OPENSSL_free(der);
                
                // 创建ECDSA公钥对象
                auto ecdsaKey = std::make_shared<crypto::ECDSAPublicKey>(keyDer);
                auto publicKey = adaptPublicKey(ecdsaKey);
                
                if (publicKey) {
                    std::vector<std::shared_ptr<PublicKey>> roleKeys = {publicKey};
                    
                    if (role == RoleName::TimestampRole) {
                        timestamp = BaseRole(role, 1, roleKeys);
                    } else if (role == RoleName::SnapshotRole) {
                        snapshot = BaseRole(role, 1, roleKeys);
                    }
                }
            }
            EC_KEY_free(ecKey);
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
        
        // 保存所有元数据文件
        std::string gunStr = gun_.empty() ? "default" : gun_;
        cache_->Set(gunStr, "root.json", rootJson);
        cache_->Set(gunStr, "targets.json", targetsJson);
        cache_->Set(gunStr, "snapshot.json", snapshotJson);
        
        // 初始化内存中的TUF Repo对象
        tufRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
        
        // 初始化Repo中的角色
        auto err = tufRepo_->InitRoot(root, targets, snapshot, timestamp);
        if (!err.ok()) {
            return err;
        }
        
        // 初始化Targets
        err = tufRepo_->InitTargets();
        if (!err.ok()) {
            return err;
        }
        
        // 初始化Snapshot
        err = tufRepo_->InitSnapshot();
        if (!err.ok()) {
            return err;
        }
        
        // 初始化Timestamp
        err = tufRepo_->InitTimestamp();
        if (!err.ok()) {
            return err;
        }
        
        return Error();
    } catch (const std::exception& e) {
        return Error(std::string("Failed to initialize TUF metadata: ") + e.what());
    }
}

Result<Target> Repository::NewTarget(const std::string& targetName, 
                                    const std::string& targetPath,
                                    const std::vector<uint8_t>& customData) {
    // 检查目标文件是否存在
    if (!fs::exists(targetPath)) {
        return Error(std::string("Target file not found: ") + targetPath);
    }
    
    // 读取文件内容
    std::ifstream file(targetPath, std::ios::binary | std::ios::ate);
    if (!file) {
        return Error(std::string("Failed to open target file: ") + targetPath);
    }
    
    // 获取文件大小
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // 读取文件内容
    std::vector<uint8_t> fileData(size);
    if (!file.read(reinterpret_cast<char*>(fileData.data()), size)) {
        return Error(std::string("Failed to read target file: ") + targetPath);
    }
    
    // 计算哈希值
    std::map<std::string, std::vector<uint8_t>> hashes;
    
    // 计算SHA-256哈希
    unsigned char hash_sha256[EVP_MAX_MD_SIZE];
    unsigned int hash_sha256_len;
    EVP_MD_CTX* mdctx_sha256 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx_sha256, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx_sha256, fileData.data(), fileData.size());
    EVP_DigestFinal_ex(mdctx_sha256, hash_sha256, &hash_sha256_len);
    EVP_MD_CTX_free(mdctx_sha256);
    
    // 存储SHA-256哈希
    std::vector<uint8_t> sha256Hash(hash_sha256, hash_sha256 + hash_sha256_len);
    hashes["sha256"] = sha256Hash;
    
    // 计算SHA-512哈希
    unsigned char hash_sha512[EVP_MAX_MD_SIZE];
    unsigned int hash_sha512_len;
    EVP_MD_CTX* mdctx_sha512 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx_sha512, EVP_sha512(), nullptr);
    EVP_DigestUpdate(mdctx_sha512, fileData.data(), fileData.size());
    EVP_DigestFinal_ex(mdctx_sha512, hash_sha512, &hash_sha512_len);
    EVP_MD_CTX_free(mdctx_sha512);
    
    // 存储SHA-512哈希
    std::vector<uint8_t> sha512Hash(hash_sha512, hash_sha512 + hash_sha512_len);
    hashes["sha512"] = sha512Hash;
    
    // 创建目标对象
    Target target;
    target.name = targetName;
    target.hashes = std::move(hashes);
    target.length = size;
    target.custom = customData;
    
    return target;
}

Error Repository::AddTarget(const Target& target, const std::vector<std::string>& roles) {
    try {
        // 验证目标哈希是否存在
        if (target.hashes.empty()) {
            return Error("No hashes specified for target \"" + target.name + "\"");
        }
        
        // 构造目标元数据
        json meta;
        meta["length"] = target.length;
        
        // 添加哈希值
        meta["hashes"] = json::object();
        for (const auto& [algorithm, hash] : target.hashes) {
            meta["hashes"][algorithm] = base64Encode(hash);
        }
        
        // 添加自定义数据（如果有）
        if (!target.custom.empty()) {
            meta["custom"] = target.custom;
        }
        
        // 序列化元数据为JSON
        std::string metaJson = meta.dump();
        std::vector<uint8_t> content(metaJson.begin(), metaJson.end());
        
        // 创建变更
        std::vector<std::string> effectiveRoles;
        if (roles.empty()) {
            // 默认使用targets角色
            effectiveRoles.push_back("targets");
        } else {
            effectiveRoles = roles;
        }
        
        // 为每个角色添加变更
        for (const auto& role : effectiveRoles) {
            auto change = std::make_shared<changelist::TUFChange>(
                changelist::ActionCreate,    // 创建操作
                role,                        // 目标角色
                changelist::TypeTargetsTarget, // 目标类型
                target.name,                 // 目标路径
                content                      // 元数据内容
            );
            
            auto err = changelist_->Add(change);
            if (!err.ok()) {
                return err;
            }
            
            // 如果是targets角色，也在内存的tufRepo中添加
            if (role == "targets" && tufRepo_) {
                RoleName roleName = RoleName::TargetsRole;
                err = tufRepo_->AddTarget(target.name, content, roleName);
                if (!err.ok()) {
                    return err;
                }
            }
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add target: ") + e.what());
    }
}

Error Repository::applyChangelist() {
    try {
        auto changes = changelist_->List();
        if (changes.empty()) {
            return Error(); // 没有变更需要应用
        }
        
        // 获取当前targets元数据
        std::string gunStr = gun_.empty() ? "default" : gun_;
        auto result = cache_->Get(gunStr, "targets.json");
        if (!result.ok()) {
            return Error("Could not load targets metadata");
        }
        
        json targetsData = result.value();
        bool targetsModified = false;
        
        // 应用每个变更
        for (const auto& change : changes) {
            // 目前只处理targets变更
            if (change->Type() == changelist::TypeTargetsTarget) {
                if (change->Action() == changelist::ActionCreate || 
                    change->Action() == changelist::ActionUpdate) {
                    // 解析元数据
                    std::string contentStr(change->Content().begin(), change->Content().end());
                    json targetMeta;
                    try {
                        targetMeta = json::parse(contentStr);
                    } catch (const std::exception& e) {
                        std::cerr << "Error parsing target metadata: " << e.what() << std::endl;
                        continue;
                    }
                    
                    // 添加到targets
                    if (!targetsData.contains("signed")) {
                        targetsData["signed"] = json::object();
                    }
                    if (!targetsData["signed"].contains("targets")) {
                        targetsData["signed"]["targets"] = json::object();
                    }
                    
                    targetsData["signed"]["targets"][change->Path()] = targetMeta;
                    targetsModified = true;
                } else if (change->Action() == changelist::ActionDelete) {
                    // 从targets中删除
                    if (targetsData.contains("signed") && 
                        targetsData["signed"].contains("targets") &&
                        targetsData["signed"]["targets"].contains(change->Path())) {
                        targetsData["signed"]["targets"].erase(change->Path());
                        targetsModified = true;
                    }
                }
            }
        }
        
        // 如果有修改，更新版本和过期时间，然后保存
        if (targetsModified) {
            // 更新元数据的version字段
            if (targetsData["signed"].contains("version")) {
                targetsData["signed"]["version"] = targetsData["signed"]["version"].get<int>() + 1;
            } else {
                targetsData["signed"]["version"] = 1;
            }
            
            // 更新元数据的expires字段
            auto expiry = getDefaultExpiry(RoleName::TargetsRole);
            auto expiryTime = std::chrono::system_clock::to_time_t(expiry);
            std::stringstream ss;
            ss << std::put_time(std::gmtime(&expiryTime), "%Y-%m-%dT%H:%M:%SZ");
            targetsData["signed"]["expires"] = ss.str();
            
            // 保存更新后的元数据
            auto err = cache_->Set(gunStr, "targets.json", targetsData);
            if (!err.ok()) {
                return Error(std::string("Failed to save target metadata: ") + err.what());
            }
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to apply changelist: ") + e.what());
    }
}

Error Repository::Publish() {
    try {
        // 尝试更新TUF元数据
        auto err = updateTUF(true);
        bool initialPublish = false;
        
        if (!err.ok()) {
            // 检查是否是首次发布
            if (std::string(err.what()).find("Repository not found") != std::string::npos) {
                // 尝试初始化仓库
                err = bootstrapRepo();
                if (!err.ok() && std::string(err.what()).find("Metadata not found") != std::string::npos) {
                    std::cout << "No TUF data found locally or remotely - initializing repository " 
                              << (gun_.empty() ? "default" : gun_) << " for the first time" << std::endl;
                    err = Initialize({});
                }
                if (!err.ok()) {
                    std::cerr << "Unable to load or initialize repository during first publish: " 
                              << err.what() << std::endl;
                    return err;
                }
                initialPublish = true;
            } else {
                std::cerr << "Could not publish Repository since we could not update: " 
                          << err.what() << std::endl;
                return err;
            }
        }
        // 应用changelist
        err = applyChangelist();
        if (!err.ok()) {
            return err;
        }
        // 清除changelist
        err = changelist_->Clear("");
        if (!err.ok()) {
            std::cerr << "Warning: Unable to clear changelist. You may want to manually delete the folder "
                      << changelist_->Location() << std::endl;
        }
        // 获取所有需要推送的元数据
        std::string gunStr = gun_.empty() ? "default" : gun_;
        std::map<std::string, std::vector<uint8_t>> updatedFiles;
        // 处理Root文件
        auto rootResult = cache_->Get(gunStr, "root.json");
        if (rootResult.ok()) {
            if (needsResigning(rootResult.value()) || initialPublish) {
                auto signedRoot = resignMetadata(rootResult.value(), "root");
                if (!signedRoot.ok()) {
                    return Error(std::string("Failed to resign root metadata: ") + signedRoot.error().what());
                }
                updatedFiles["root"] = signedRoot.value();
            } else {
                std::string rootStr = rootResult.value().dump();
                updatedFiles["root"] = std::vector<uint8_t>(rootStr.begin(), rootStr.end());
            }
        }
        // 处理Targets文件
        auto targetsResult = cache_->Get(gunStr, "targets.json");
        if (targetsResult.ok()) {
            if (needsResigning(targetsResult.value()) || initialPublish) {
                auto signedTargets = resignMetadata(targetsResult.value(), "targets");
                if (!signedTargets.ok()) {
                    return Error(std::string("Failed to resign targets metadata: ") + signedTargets.error().what());
                }
                updatedFiles["targets"] = signedTargets.value();
            } else {
                std::string targetsStr = targetsResult.value().dump();
                updatedFiles["targets"] = std::vector<uint8_t>(targetsStr.begin(), targetsStr.end());
            }
        }
        // 处理Snapshot文件
        auto snapshotResult = cache_->Get(gunStr, "snapshot.json");
        if (snapshotResult.ok()) {
            if (needsResigning(snapshotResult.value()) || initialPublish) {
                auto signedSnapshot = resignMetadata(snapshotResult.value(), "snapshot");
                if (!signedSnapshot.ok()) {
                    std::cout << "Client does not have the key to sign snapshot. "
                              << "Assuming that server should sign the snapshot." << std::endl;
                } else {
                    updatedFiles["snapshot"] = signedSnapshot.value();
                }
            } else {
                std::string snapshotStr = snapshotResult.value().dump();
                updatedFiles["snapshot"] = std::vector<uint8_t>(snapshotStr.begin(), snapshotStr.end());
            }
        } else {
            // 如果没有snapshot文件，尝试初始化
            err = initializeSnapshot();
            if (!err.ok()) {
                std::cerr << "Failed to initialize snapshot: " << err.what() << std::endl;
                return err;
            }
        }
        // 推送到远程服务器
        for (const auto& [role, data] : updatedFiles) {
            err = remoteStore_->SetRemote(gunStr, role, data);
            if (!err.ok()) {
                return Error(std::string("Failed to publish ") + role + " metadata: " + err.what());
            }
        }
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to publish: ") + e.what());
    }
}

Error Repository::updateTUF(bool force) {
    try {
        std::string gunStr = gun_.empty() ? "default" : gun_;
        
        // 尝试从远程获取最新的元数据
        auto rootResult = remoteStore_->GetRemote(gunStr, "root");
        if (!rootResult.ok()) {
            return Error("Repository not found");
        }
        
        // 更新本地缓存
        auto err = cache_->Set(gunStr, "root.json", rootResult.value());
        if (!err.ok()) {
            return err;
        }
        
        // 获取并更新其他角色的元数据
        std::vector<std::string> roles = {"targets", "snapshot"};
        for (const auto& role : roles) {
            auto result = remoteStore_->GetRemote(gunStr, role);
            if (result.ok()) {
                err = cache_->Set(gunStr, role + ".json", result.value());
                if (!err.ok()) {
                    return err;
                }
            }
        }
        
        return Error();
    } catch (const std::exception& e) {
        return Error(std::string("Failed to update TUF: ") + e.what());
    }
}

Error Repository::bootstrapRepo() {
    try {
        std::string gunStr = gun_.empty() ? "default" : gun_;
        
        // 尝试从本地缓存加载元数据
        auto rootResult = cache_->Get(gunStr, "root.json");
        if (!rootResult.ok()) {
            return Error("Metadata not found");
        }
        
        return Error();
    } catch (const std::exception& e) {
        return Error(std::string("Failed to bootstrap repository: ") + e.what());
    }
}

bool Repository::needsResigning(const std::vector<uint8_t>& metadata) {
    try {
        // 解析元数据
        json meta = json::parse(metadata);
        
        // 检查过期时间
        if (meta.contains("expires")) {
            auto expires = meta["expires"].get<std::string>();
            auto expiryTime = std::chrono::system_clock::from_time_t(
                std::stoll(expires));
            auto now = std::chrono::system_clock::now();
            
            // 如果过期时间在24小时内，需要重新签名
            return (expiryTime - now) < std::chrono::hours(24);
        }
        
        return false;
    } catch (const std::exception&) {
        return true; // 如果解析失败，为了安全起见重新签名
    }
}

Result<std::vector<uint8_t>> Repository::resignMetadata(const std::vector<uint8_t>& metadata, const std::string& role) {
    try {
        // 解析元数据
        json meta = json::parse(metadata);
        // 更新签名时间
        auto now = std::chrono::system_clock::now();
        auto nowTimeT = std::chrono::system_clock::to_time_t(now);
        meta["signed"]["timestamp"] = nowTimeT;
        // 更新过期时间
        RoleName roleName;
        if (role == "root") {
            roleName = RoleName::RootRole;
        } else if (role == "targets") {
            roleName = RoleName::TargetsRole;
        } else if (role == "snapshot") {
            roleName = RoleName::SnapshotRole;
        } else {
            return Result<std::vector<uint8_t>>(Error("Invalid role: " + role));
        }
        auto expiry = getDefaultExpiry(roleName);
        meta["signed"]["expires"] = std::chrono::system_clock::to_time_t(expiry);
        // 获取角色的所有密钥
        auto keys = cryptoService_.ListKeys(roleName);
        if (keys.empty()) {
            return Result<std::vector<uint8_t>>(Error("No keys found for role: " + role));
        }
        // 使用第一个密钥重新签名
        auto keyResult = cryptoService_.GetPrivateKey(keys[0]);
        if (!keyResult.ok()) {
            return Result<std::vector<uint8_t>>(keyResult.error());
        }
        // 类型转换，确保有Sign方法
        auto notaryPrivKey = std::dynamic_pointer_cast<notary::PrivateKey>(keyResult.value());
        if (!notaryPrivKey) {
            return Result<std::vector<uint8_t>>(Error("PrivateKey类型转换失败，无法签名"));
        }
        // 序列化元数据
        std::string metadataStr = meta["signed"].dump();
        std::vector<uint8_t> metadataBytes(metadataStr.begin(), metadataStr.end());
        // 使用私钥签名
        auto signatureResult = notaryPrivKey->Sign(metadataBytes);
        if (!signatureResult.ok()) {
            return Result<std::vector<uint8_t>>(signatureResult.error());
        }
        // 更新签名
        meta["signatures"] = json::array();
        meta["signatures"].push_back({
            {"keyid", keys[0]},
            {"sig", base64Encode(signatureResult.value())}
        });
        // 返回新的元数据
        std::string resultStr = meta.dump();
        std::vector<uint8_t> result(resultStr.begin(), resultStr.end());
        return Result<std::vector<uint8_t>>(result);
    } catch (const std::exception& e) {
        return Result<std::vector<uint8_t>>(Error(std::string("Failed to resign metadata: ") + e.what()));
    }
}

Error Repository::initializeSnapshot() {
    try {
        std::string gunStr = gun_.empty() ? "default" : gun_;
        
        // 创建新的snapshot元数据
        json snapshot = {
            {"signed", {
                {"_type", "snapshot"},
                {"version", 1},
                {"expires", std::to_string(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        getDefaultExpiry(RoleName::SnapshotRole).time_since_epoch()).count())},
                {"meta", {}}
            }}
        };
        
        // 获取并添加targets元数据
        auto targetsResult = cache_->Get(gunStr, "targets.json");
        if (targetsResult.ok()) {
            auto targetsHash = calculateHashes(targetsResult.value());
            snapshot["signed"]["meta"]["targets.json"] = createFileMeta(targetsHash);
        }
        
        // 序列化并存储
        std::string jsonStr = snapshot.dump();
        std::vector<uint8_t> snapshotData(jsonStr.begin(), jsonStr.end());
        return cache_->Set(gunStr, "snapshot.json", snapshotData);
    } catch (const std::exception& e) {
        return Error(std::string("Failed to initialize snapshot: ") + e.what());
    }
}

} // namespace notary 