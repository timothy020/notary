#include <iostream>
#include <fstream>
#include <CLI/CLI.hpp>
#include "notary/client/repository.hpp"
#include "notary/storage/keystore.hpp"
#include "notary/passRetriever/passRetriever.hpp"
#include "notary/crypto/crypto_service.hpp"
#include "notary/utils/tools.hpp"
#include "notary/utils/x509.hpp"
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <ctime>

using namespace notary;

// 使用标准filesystem命名空间
namespace fs = std::filesystem;

// 密钥信息结构（用于排序和显示）
struct KeyDisplayInfo {
    std::string gun;       // 仓库名称
    std::string role;         // 密钥角色
    std::string keyID;     // 密钥ID
    std::string location;  // 密钥存储位置
    
    KeyDisplayInfo(const std::string& g, const std::string& r, const std::string& id, const std::string& loc)
        : gun(g), role(r), keyID(id), location(loc) {}
};

// 字符串截断函数（对应Go的truncateWithEllipsis）
std::string truncateWithEllipsis(const std::string& str, size_t maxWidth, bool leftTruncate = false) {
    if (str.length() <= maxWidth) {
        return str;
    }
    
    if (leftTruncate) {
        return "..." + str.substr(str.length() - (maxWidth - 3));
    } else {
        return str.substr(0, maxWidth - 3) + "...";
    }
}

// 密钥信息排序比较器（对应Go的keyInfoSorter）
bool compareKeyInfo(const KeyDisplayInfo& a, const KeyDisplayInfo& b) {
    // 特殊处理root角色 - root角色总是排在前面
    if (a.role != b.role) {
        if (a.role == ROOT_ROLE) {
            return true;
        }
        if (b.role == ROOT_ROLE) {
            return false;
        }
        // 其他角色按字符串顺序排序
    }
    
    // 排序顺序：GUN, role, keyID, location
    std::vector<std::string> orderedA = {
        a.gun, 
        a.role, 
        a.keyID, 
        a.location
    };
    std::vector<std::string> orderedB = {
        b.gun, 
        b.role, 
        b.keyID, 
        b.location
    };
    
    for (size_t i = 0; i < 4; ++i) {
        if (orderedA[i] < orderedB[i]) {
            return true;
        } else if (orderedA[i] > orderedB[i]) {
            return false;
        }
        // 继续比较下一个字段
    }
    
    return false; // 完全相等
}

// 美化打印密钥列表（对应Go的prettyPrintKeys函数）
void prettyPrintKeys(const std::vector<std::unique_ptr<storage::GenericKeyStore>>& keyStores) {
    const size_t maxGUNWidth = 25;
    const size_t maxLocWidth = 40;
    
    std::vector<KeyDisplayInfo> info;
    
    // 从所有密钥存储中收集密钥信息
    for (const auto& store : keyStores) {
        auto keyInfoMap = store->ListKeys();
        for (const auto& [keyID, keyInfo] : keyInfoMap) {
            info.emplace_back(keyInfo.gun, keyInfo.role, keyID, store->Name());
        }
    }
    
    // 如果没有密钥，显示提示信息
    if (info.empty()) {
        std::cout << "No signing keys found." << std::endl;
        return;
    }
    
    // 排序密钥信息
    std::sort(info.begin(), info.end(), compareKeyInfo);
    
    // 打印表头
    std::cout << std::left
              << std::setw(15) << "ROLE"
              << std::setw(maxGUNWidth + 2) << "GUN"
              << std::setw(66) << "KEY ID"  // 64位哈希 + 一些空间
              << std::setw(maxLocWidth + 2) << "LOCATION"
              << std::endl;
    
    // 打印分隔线（对应Go版本的格式）
    std::cout << std::left
              << std::setw(15) << "----"
              << std::setw(maxGUNWidth + 2) << "---"
              << std::setw(66) << "------"
              << std::setw(maxLocWidth + 2) << "--------"
              << std::endl;
    
    // 打印每个密钥的信息
    for (const auto& keyInfo : info) {
        std::cout << std::left
                  << std::setw(15) << keyInfo.role
                  << std::setw(maxGUNWidth + 2) << truncateWithEllipsis(keyInfo.gun, maxGUNWidth, true)
                  << std::setw(66) << keyInfo.keyID
                  << std::setw(maxLocWidth + 2) << truncateWithEllipsis(keyInfo.location, maxLocWidth, true)
                  << std::endl;
    }
}

// 确认函数（对应Go的askConfirm）
bool askConfirm(std::istream& input) {
    std::string response;
    if (!std::getline(input, response)) {
        return false;
    }
    
    // 去除首尾空格并转换为小写
    response.erase(0, response.find_first_not_of(" \t"));
    response.erase(response.find_last_not_of(" \t") + 1);
    std::transform(response.begin(), response.end(), response.begin(), ::tolower);
    
    return (response == "y" || response == "yes");
}

// 结构存储找到的密钥信息
struct FoundKeyInfo {
    std::string keypath;
    std::string role;
    std::string location;
    storage::GenericKeyStore* store;
    
    FoundKeyInfo(const std::string& path, const std::string& r, const std::string& loc, 
                 storage::GenericKeyStore* s) 
        : keypath(path), role(r), location(loc), store(s) {}
};

// 交互式删除密钥（对应Go的removeKeyInteractively）
Error removeKeyInteractively(const std::vector<std::unique_ptr<storage::GenericKeyStore>>& keyStores, 
                            const std::string& keyID,
                            std::istream& input, 
                            std::ostream& output) {
    
    std::vector<FoundKeyInfo> foundKeys;
    
    // 搜索所有密钥存储中的匹配密钥
    for (const auto& store : keyStores) {
        auto keyInfoMap = store->ListKeys();
        for (const auto& [fullKeyID, keyInfo] : keyInfoMap) {
            // 检查keyID是否匹配（完整匹配或以keyID开头）
            if (fullKeyID == keyID || fullKeyID.find(keyID) == 0) {
                foundKeys.emplace_back(fullKeyID, keyInfo.role, 
                                     store->Name(), store.get());
            }
        }
    }
    
    if (foundKeys.empty()) {
        return Error("no key with ID " + keyID + " found");
    }
    
    // 如果找到多个密钥，让用户选择
    if (foundKeys.size() > 1) {
        while (true) {
            // 询问用户选择删除哪个密钥
            output << "Found the following matching keys:" << std::endl;
            for (size_t i = 0; i < foundKeys.size(); ++i) {
                const auto& info = foundKeys[i];
                output << "\t" << (i + 1) << ". " << info.keypath << ": " 
                       << info.role << " (" << info.location << ")" << std::endl;
            }
            output << "Which would you like to delete?  Please enter a number:  ";
            output.flush();
            
            std::string result;
            if (!std::getline(input, result)) {
                return Error("Failed to read user input");
            }
            
            // 尝试解析用户输入的数字
            try {
                int index = std::stoi(result);
                if (index >= 1 && index <= static_cast<int>(foundKeys.size())) {
                    // 用户选择有效，只保留选中的密钥
                    FoundKeyInfo selected = foundKeys[index - 1];
                    foundKeys.clear();
                    foundKeys.push_back(selected);
                    output << std::endl;
                    break;
                }
            } catch (const std::exception&) {
                // 解析失败，继续循环
            }
            
            output << "\nInvalid choice: " << result << std::endl;
        }
    }
    
    // 现在应该只有一个密钥，请求确认删除
    const auto& keyInfo = foundKeys[0];
    std::string keyDescription = keyInfo.keypath + " (role " + keyInfo.role + ") from " + keyInfo.location;
    
    output << "Are you sure you want to remove " << keyDescription << "?  (yes/no)  ";
    output.flush();
    
    if (!askConfirm(input)) {
        output << "\nAborting action." << std::endl;
        return Error(); // 不是错误，只是用户取消
    }
    
    // 执行删除
    auto removeErr = keyInfo.store->RemoveKey(keyInfo.keypath);
    if (removeErr.hasError()) {
        return removeErr;
    }
    
    output << "\nDeleted " << keyDescription << "." << std::endl;
    return Error(); // 成功
}

// 获取密钥存储列表（对应Go的getKeyStores）
std::vector<std::unique_ptr<storage::GenericKeyStore>> getKeyStores(
    const std::string& trustDir, 
    passphrase::PassRetriever passRetriever,
    bool withHardware = false,
    bool hardwareBackup = false) {
    
    std::vector<std::unique_ptr<storage::GenericKeyStore>> keyStores;
    
    // 创建文件密钥存储 - 在trustDir后面添加"private"目录（对应Go的NewPrivateKeyFileStorage）
    std::string privateDir = trustDir + "/private";
    auto fileKeyStore = storage::NewKeyFileStore(privateDir, passRetriever);
    if (fileKeyStore) {
        keyStores.push_back(std::move(fileKeyStore));
    }
    
    // TODO: 如果需要支持硬件密钥存储（如YubiKey），在这里添加
    // 目前只支持文件存储
    if (withHardware) {
        utils::GetLogger().Warn("Hardware key stores not yet implemented in C++ version");
    }
    
    return keyStores;
}

// 美化打印委托角色列表 (对应Go的prettyPrintRoles函数)
void prettyPrintRoles(const std::vector<tuf::DelegationRole>& roles, const std::string& roleType = "delegations") {
    if (roles.empty()) {
        std::cout << "\nNo " << roleType << " present in this repository." << std::endl;
        return;
    }
    
    // 计算列宽 (对应Go的计算最大宽度逻辑)
    size_t maxRoleWidth = 4;     // "ROLE"的长度
    size_t maxKeysWidth = 4;     // "KEYS"的长度
    size_t maxThresholdWidth = 9; // "THRESHOLD"的长度
    size_t maxPathsWidth = 5;    // "PATHS"的长度
    
    for (const auto& role : roles) {
        maxRoleWidth = std::max(maxRoleWidth, role.Name.length());
        maxKeysWidth = std::max(maxKeysWidth, std::to_string(role.BaseRoleInfo.Keys().size()).length());
        maxThresholdWidth = std::max(maxThresholdWidth, std::to_string(role.BaseRoleInfo.Threshold()).length());
        
        // 计算路径字符串的长度
        std::string pathsStr = "";
        for (size_t i = 0; i < role.Paths.size(); ++i) {
            if (i > 0) pathsStr += ", ";
            pathsStr += role.Paths[i];
        }
        maxPathsWidth = std::max(maxPathsWidth, pathsStr.length());
    }
    
    // 打印表头 (对应Go的fmt.Fprintf)
    std::cout << std::endl;
    std::cout << std::left 
              << std::setw(maxRoleWidth + 2) << "ROLE"
              << std::setw(maxKeysWidth + 2) << "KEYS"
              << std::setw(maxThresholdWidth + 2) << "THRESHOLD"
              << std::setw(maxPathsWidth + 2) << "PATHS"
              << std::endl;
    
    // 打印分隔线
    std::cout << std::string(maxRoleWidth + 2, '-') 
              << std::string(maxKeysWidth + 2, '-')
              << std::string(maxThresholdWidth + 2, '-')
              << std::string(maxPathsWidth + 2, '-')
              << std::endl;
    
    // 打印每个角色 (对应Go的遍历roles逻辑)
    for (const auto& role : roles) {
        // 构建路径字符串
        std::string pathsStr = "";
        for (size_t i = 0; i < role.Paths.size(); ++i) {
            if (i > 0) pathsStr += ", ";
            pathsStr += role.Paths[i];
        }
        
        // 打印角色信息
        std::cout << std::left
                  << std::setw(maxRoleWidth + 2) << role.Name
                  << std::setw(maxKeysWidth + 2) << role.BaseRoleInfo.Keys().size()
                  << std::setw(maxThresholdWidth + 2) << role.BaseRoleInfo.Threshold()
                  << std::setw(maxPathsWidth + 2) << pathsStr
                  << std::endl;
    }
    std::cout << std::endl;
}

// 美化打印目标列表 (对应Go的prettyPrintTargets函数)
void prettyPrintTargets(const std::vector<TargetWithRole>& targets) {
    if (targets.empty()) {
        std::cout << "No targets present in this repository." << std::endl;
        return;
    }
    
    // 计算列宽 (对应Go的计算最大宽度逻辑)
    size_t maxNameWidth = 4;  // "NAME"的长度
    size_t maxSizeWidth = 4;  // "SIZE"的长度
    size_t maxRoleWidth = 4;  // "ROLE"的长度
    
    for (const auto& targetWithRole : targets) {
        maxNameWidth = std::max(maxNameWidth, targetWithRole.target.name.length());
        maxSizeWidth = std::max(maxSizeWidth, std::to_string(targetWithRole.target.length).length());
        maxRoleWidth = std::max(maxRoleWidth, targetWithRole.role.length());
    }
    
    // 打印表头 (对应Go的fmt.Fprintf)
    std::cout << std::left 
              << std::setw(maxNameWidth + 2) << "NAME"
              << std::setw(16) << "DIGEST"
              << std::setw(maxSizeWidth + 2) << "SIZE (BYTES)"
              << std::setw(maxRoleWidth + 2) << "ROLE"
              << std::endl;
    
    // 打印分隔线
    std::cout << std::string(maxNameWidth + 2, '-') 
              << std::string(16, '-')
              << std::string(maxSizeWidth + 2, '-')
              << std::string(maxRoleWidth + 2, '-')
              << std::endl;
    
    // 打印每个目标 (对应Go的遍历targets逻辑)
    for (const auto& targetWithRole : targets) {
        const auto& target = targetWithRole.target;
        
        // 获取第一个哈希值用于显示 (对应Go的target.Hashes.Hex())
        std::string digest = "N/A";
        if (!target.hashes.empty()) {
            const auto& firstHash = target.hashes.begin()->second;
            if (!firstHash.empty()) {
                // 将哈希值转换为十六进制字符串，只显示前12个字符
                std::stringstream ss;
                for (size_t i = 0; i < std::min(firstHash.size(), size_t(6)); ++i) {
                    ss << std::hex << std::setfill('0') << std::setw(2) 
                       << static_cast<unsigned>(firstHash[i]);
                }
                digest = ss.str();
            }
        }
        
        // 打印目标信息
        std::cout << std::left
                  << std::setw(maxNameWidth + 2) << target.name
                  << std::setw(16) << digest
                  << std::setw(maxSizeWidth + 2) << target.length
                  << std::setw(maxRoleWidth + 2) << targetWithRole.role
                  << std::endl;
    }
}

// 美化打印更改列表 (对应Go的changelist状态显示)
void prettyPrintChanges(const std::vector<std::shared_ptr<changelist::Change>>& changes) {
    if (changes.empty()) {
        std::cout << "No unpublished changes for this repository." << std::endl;
        std::cout << "To sign and publish changes to this repository, run `notary publish <gun>`" << std::endl;
        return;
    }
    
    // 计算列宽
    size_t maxActionWidth = 6;  // "ACTION"的长度
    size_t maxScopeWidth = 5;   // "SCOPE"的长度  
    size_t maxTypeWidth = 4;    // "TYPE"的长度
    size_t maxPathWidth = 4;    // "PATH"的长度
    
    for (const auto& change : changes) {
        maxActionWidth = std::max(maxActionWidth, change->Action().length());
        maxScopeWidth = std::max(maxScopeWidth, change->Scope().length());
        maxTypeWidth = std::max(maxTypeWidth, change->Type().length());
        maxPathWidth = std::max(maxPathWidth, change->Path().length());
    }
    
    // 打印表头
    std::cout << std::left
              << std::setw(4) << "#"
              << std::setw(maxActionWidth + 2) << "ACTION"
              << std::setw(maxScopeWidth + 2) << "SCOPE"
              << std::setw(maxTypeWidth + 2) << "TYPE"
              << std::setw(maxPathWidth + 2) << "PATH"
              << std::endl;
    
    // 打印分隔线
    std::cout << std::string(4, '-')
              << std::string(maxActionWidth + 2, '-')
              << std::string(maxScopeWidth + 2, '-')
              << std::string(maxTypeWidth + 2, '-')
              << std::string(maxPathWidth + 2, '-')
              << std::endl;
    
    // 打印每个更改
    for (size_t i = 0; i < changes.size(); ++i) {
        const auto& change = changes[i];
        
        std::cout << std::left
                  << std::setw(4) << (i)  // 更改编号从0开始
                  << std::setw(maxActionWidth + 2) << change->Action()
                  << std::setw(maxScopeWidth + 2) << change->Scope()
                  << std::setw(maxTypeWidth + 2) << change->Type()
                  << std::setw(maxPathWidth + 2) << change->Path()
                  << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "To sign and publish changes to this repository, run `notary publish " << std::endl;
}

// 加载配置
Error loadConfig(const std::string& configFile, std::string& trustDir, std::string& serverURL) {
    // 如果没有指定配置文件，使用默认值
    if (trustDir.empty()) {
        trustDir = fs::current_path().string() + "/trust/";
    }
    
    if (serverURL.empty()) {
        serverURL = "http://localhost:4443";
    }
    
    // 确保信任目录存在
    try {
        if (!fs::exists(trustDir)) {
            fs::create_directories(trustDir);
        }
    } catch (const std::exception& e) {
        return Error(std::string("Failed to create trust directory: ") + e.what());
    }
    
    return Error();
}

// 导入根密钥
Error importRootKey(const std::string& rootKeyPath, std::vector<std::string>& rootKeyIDs) {
    if (rootKeyPath.empty()) {
        return Error();
    }
    
    // TODO: 实现从文件加载根密钥
    // 目前简单地将路径添加到ID列表
    rootKeyIDs.push_back(rootKeyPath);
    return Error();
}

// 导入根证书
Error importRootCert(const std::string& rootCertPath, std::vector<std::string>& rootCerts) {
    if (rootCertPath.empty()) {
        return Error();
    }
    
    // TODO: 实现从文件加载根证书
    rootCerts.push_back(rootCertPath);
    return Error();
}

// 可能自动发布
Error maybeAutoPublish(bool autoPublish, const std::string& gun, 
                     const std::string& serverURL, Repository& repo) {
    if (!autoPublish) {
        return Error();
    }
    utils::GetLogger().Info("Publishing changes to " + gun, utils::LogContext()
        .With("serverURL", serverURL));
    return repo.Publish(); // 调用Repository类的Publish方法
}



// 生成密钥到文件 - 对应Go版本的generateKeyToFile函数
Error generateKeyToFile(const std::string& role, 
                       const std::string& algorithm, 
                       passphrase::PassRetriever passRetriever,
                       const std::string& outFile) {
    try {
        // 1. 验证算法 (对应Go版本的allowedCiphers检查)
        if (algorithm != "ecdsa") {
            return Error("algorithm not allowed, possible values are: ECDSA");
        }
        
        // 2. 生成私钥 (对应Go版本的tufutils.GenerateKey(algorithm))
        crypto::CryptoService cryptoService;
        auto keyResult = cryptoService.GeneratePrivateKey(algorithm);
        if (!keyResult.ok()) {
            return Error("Failed to generate private key: " + keyResult.error().what());
        }
        
        auto privKey = keyResult.value();
        
        // 从私钥获取公钥 (对应Go版本的data.PublicKeyFromPrivate(privKey))
        auto pubKey = privKey->GetPublicKey();
        
        // 3. 获取密码 (对应Go版本的密码获取循环)
        std::string chosenPassphrase;
        bool giveup = false;
        std::string keyID = privKey->ID();
        int attempts = 0;
        
        for (attempts = 0; attempts <= 10; ++attempts) {
            auto passResult = passRetriever(keyID, "", true, attempts);
            auto passphrase = std::get<0>(passResult);
            auto giveupFlag = std::get<1>(passResult);
            auto error = std::get<2>(passResult);
            
            if (error.hasError()) {
                if (giveupFlag || attempts >= 10) {
                    return Error("Password retrieval attempts exceeded");
                }
                continue;
            }
            
            if (passphrase.empty() && giveupFlag) {
                giveup = true;
                break;
            }
            if (!passphrase.empty()) {
                chosenPassphrase = passphrase;
                break;
            }
        }
        
        if (giveup || attempts > 10) {
            return Error("Password retrieval attempts exceeded");
        }
        
        if (chosenPassphrase.empty()) {
            return Error("No password provided");
        }
        
        // 4. 转换私钥为PKCS8格式 (对应Go版本的tufutils.ConvertPrivateKeyToPKCS8)
        std::string pemPrivKey;
        try {
            pemPrivKey = utils::ConvertPrivateKeyToPKCS8(privKey, role, "", chosenPassphrase);
        } catch (const std::exception& e) {
            return Error("Failed to convert private key to PKCS8: " + std::string(e.what()));
        }
        
        // 5. 生成文件名 (对应Go版本的strings.Join逻辑)
        // privFileName := strings.Join([]string{outFile, "key"}, "-")
        // privFile := strings.Join([]string{privFileName, "pem"}, ".")
        // pubFile := strings.Join([]string{outFile, "pem"}, ".")
        std::string privFileName = outFile + "-key";
                 std::string privFile = privFileName + ".pem";
         std::string pubFile = outFile + ".pem";
         
         // 6. 写入私钥文件 (对应Go版本的ioutil.WriteFile(privFile, pemPrivKey, notary.PrivNoExecPerms))
         try {
                          std::ofstream privFileStream(privFile, std::ios::binary);
             if (!privFileStream) {
                 return Error("Failed to create private key file: " + privFile);
             }
             privFileStream.write(pemPrivKey.c_str(), pemPrivKey.size());
             privFileStream.close();
             
             // 设置文件权限为600 (只有所有者可读写)
#ifndef _WIN32
             if (chmod(privFile.c_str(), S_IRUSR | S_IWUSR) != 0) {
                 utils::GetLogger().Warn("Failed to set private key file permissions");
             }
#endif
        } catch (const std::exception& e) {
            return Error("Failed to write private key file: " + std::string(e.what()));
        }
        
        // 6. 创建公钥PEM格式 (对应Go版本的pem.Block)
        // 获取公钥字节数据 (对应Go版本的pubKey.Public())
        auto publicBytes = pubKey->Public();
        
        // 创建PEM Block结构 (对应Go版本的pem.Block)
        // Type: "PUBLIC KEY"
        // Headers: map[string]string{"role": role}
        // Bytes: pubKey.Public()
        std::string publicPEM = "-----BEGIN PUBLIC KEY-----\n";
        
        // 添加角色头部信息 (对应Go版本的Headers: map[string]string{"role": role})
        if (!role.empty()) {
            publicPEM += "role: " + role + "\n";
        }
        publicPEM += "\n";
        
        // 将公钥字节数据进行Base64编码并添加到PEM中
        std::string base64Data = utils::Base64Encode(publicBytes);
        
        // 按64字符一行分割Base64数据
        size_t pos = 0;
        while (pos < base64Data.length()) {
            size_t lineLen = std::min(size_t(64), base64Data.length() - pos);
            publicPEM += base64Data.substr(pos, lineLen) + "\n";
            pos += lineLen;
        }
                 
         publicPEM += "-----END PUBLIC KEY-----\n";
         
         // 7. 写入公钥文件 (对应Go版本的ioutil.WriteFile(pubFile, pem.EncodeToMemory(&pubPEM), notary.PrivNoExecPerms))
         try {
             std::ofstream pubFileStream(pubFile, std::ios::binary);
             if (!pubFileStream) {
                 return Error("Failed to create public key file: " + pubFile);
             }
             pubFileStream.write(publicPEM.c_str(), publicPEM.size());
             pubFileStream.close();
             
             // 设置文件权限为644 (所有者可读写，其他人只读)
#ifndef _WIN32
             if (chmod(pubFile.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) {
                 utils::GetLogger().Warn("Failed to set public key file permissions");
             }
#endif
        } catch (const std::exception& e) {
            return Error("Failed to write public key file: " + std::string(e.what()));
        }
        

        
                 std::cout << "Generated new " << algorithm << " " << role 
                  << " key with keyID: " << pubKey->ID() << std::endl;
         std::cout << "Private key saved to: " << privFile << std::endl;
         std::cout << "Public key saved to: " << pubFile << std::endl;
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error("Failed to generate key to file: " + std::string(e.what()));
    }
}

// 加载自定义数据
Result<std::vector<uint8_t>> getTargetCustom(const std::string& customPath) {
    try {
        if (customPath.empty()) {
            return std::vector<uint8_t>{};
        }
        
        // 检查文件是否存在
        if (!fs::exists(customPath)) {
            return Error("Custom data file not found: " + customPath);
        }
        
        // 读取文件内容
        std::ifstream file(customPath, std::ios::binary | std::ios::ate);
        if (!file) {
            return Error("Failed to open custom data file: " + customPath);
        }
        
        // 获取文件大小
        auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // 读取文件内容
        std::vector<uint8_t> customData(size);
        if (!file.read(reinterpret_cast<char*>(customData.data()), size)) {
            return Error("Failed to read custom data file: " + customPath);
        }
        
        return customData;
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to load custom data: ") + e.what());
    }
}

// ingestPublicKeys函数实现 - 对应Go版本的ingestPublicKeys函数
// 读取PEM格式的公钥文件并解析为PublicKey对象
Result<std::vector<std::shared_ptr<crypto::PublicKey>>> ingestPublicKeys(const std::vector<std::string>& pubKeyPaths) {
    try {
        std::vector<std::shared_ptr<crypto::PublicKey>> pubKeys;
        pubKeys.reserve(pubKeyPaths.size());
        
        // 遍历每个公钥文件路径
        for (const auto& pubKeyPath : pubKeyPaths) {
            // 检查文件是否存在
            if (!fs::exists(pubKeyPath)) {
                return Error("File for public key does not exist: " + pubKeyPath);
            }
            
            utils::GetLogger().Info("Processing public key file: " + pubKeyPath);
            
            // 读取公钥文件内容
            std::ifstream file(pubKeyPath);
            if (!file.is_open()) {
                return Error("Unable to read public key from file: " + pubKeyPath);
            }
            
            // 读取文件内容到字符串
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string pemStr = buffer.str();
            
            // 查找PEM块的开始和结束
            size_t beginPos = pemStr.find("-----BEGIN");
            size_t endPos = pemStr.find("-----END");
            if (beginPos == std::string::npos || endPos == std::string::npos) {
                return Error("Invalid PEM format in file: " + pubKeyPath);
            }
            
            // 提取PEM块内容
            std::string pemBlock = pemStr.substr(beginPos, endPos + 25 - beginPos);
            
            // 提取role信息（如果存在）
            std::string role;
            size_t rolePos = pemBlock.find("role:");
            if (rolePos != std::string::npos) {
                size_t roleStart = rolePos + 5; // "role:"的长度
                size_t roleEnd = pemBlock.find_first_of("\r\n", roleStart);
                if (roleEnd != std::string::npos) {
                    role = pemBlock.substr(roleStart, roleEnd - roleStart);
                    // 去除前后空格
                    role.erase(0, role.find_first_not_of(" \t"));
                    role.erase(role.find_last_not_of(" \t") + 1);
                    utils::GetLogger().Info("Found role information", 
                        utils::LogContext().With("role", role));
                }
            }
            
            // 移除role信息行，保留PEM头部和Base64编码部分
            std::string cleanPem;
            std::istringstream pemStream(pemBlock);
            std::string line;
            bool foundBegin = false;
            bool isBase64Section = false;
            
            while (std::getline(pemStream, line)) {
                // 去除行尾的\r
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                
                if (line.find("-----BEGIN") != std::string::npos) {
                    foundBegin = true;
                    isBase64Section = true;
                    cleanPem += line + "\n";
                } else if (line.find("-----END") != std::string::npos) {
                    isBase64Section = false;
                    cleanPem += line + "\n";
                } else if (foundBegin && isBase64Section) {
                    // 跳过role行和空行
                    if (line.find("role:") == std::string::npos && !line.empty()) {
                        cleanPem += line + "\n";
                    }
                }
            }
            
            // 将处理后的PEM数据转换为字节数组
            std::vector<uint8_t> cleanPubKeyBytes(cleanPem.begin(), cleanPem.end());
            
            // 解析PEM格式公钥或证书
            try {
                std::shared_ptr<crypto::PublicKey> pubKey = nullptr;
                
                // 先尝试作为证书解析
                try {
                    auto certs = utils::LoadCertBundleFromPEM(cleanPubKeyBytes);
                    if (!certs.empty()) {
                        pubKey = utils::CertToKey(*certs[0]);
                        if (pubKey) {
                            utils::GetLogger().Info("Successfully loaded public key from certificate", 
                                utils::LogContext()
                                    .With("file", pubKeyPath)
                                    .With("keyID", pubKey->ID())
                                    .With("algorithm", pubKey->Algorithm())
                                    .With("role", role));
                        }
                    }
                } catch (const std::exception& certErr) {
                    utils::GetLogger().Debug("Certificate parsing failed, trying public key format", 
                        utils::LogContext()
                            .With("file", pubKeyPath)
                            .With("certError", certErr.what()));
                }
                
                // 如果证书解析失败，尝试直接解析公钥
                if (!pubKey) {
                    try {
                        BIO* bio = BIO_new_mem_buf(cleanPubKeyBytes.data(), static_cast<int>(cleanPubKeyBytes.size()));
                        if (!bio) {
                            return Error("Failed to create BIO for PEM data in file: " + pubKeyPath);
                        }
                        
                        EVP_PKEY* evpKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
                        BIO_free(bio);
                        
                        if (evpKey) {
                            if (EVP_PKEY_id(evpKey) == EVP_PKEY_EC) {
                                unsigned char* der = nullptr;
                                int derLen = i2d_PUBKEY(evpKey, &der);
                                if (derLen > 0 && der) {
                                    std::vector<uint8_t> keyDer(der, der + derLen);
                                    OPENSSL_free(der);
                                    pubKey = crypto::NewPublicKey(ECDSA_KEY, keyDer);
                                }
                            } else if (EVP_PKEY_id(evpKey) == EVP_PKEY_RSA) {
                                unsigned char* der = nullptr;
                                int derLen = i2d_PUBKEY(evpKey, &der);
                                if (derLen > 0 && der) {
                                    std::vector<uint8_t> keyDer(der, der + derLen);
                                    OPENSSL_free(der);
                                    pubKey = crypto::NewPublicKey(RSA_KEY, keyDer);
                                }
                            }
                            EVP_PKEY_free(evpKey);
                            
                            if (pubKey) {
                                utils::GetLogger().Info("Successfully loaded public key from PEM", 
                                    utils::LogContext()
                                        .With("file", pubKeyPath)
                                        .With("keyID", pubKey->ID())
                                        .With("algorithm", pubKey->Algorithm())
                                        .With("role", role));
                            }
                        }
                    } catch (const std::exception& keyErr) {
                        utils::GetLogger().Debug("Public key parsing also failed", 
                            utils::LogContext()
                                .With("file", pubKeyPath)
                                .With("keyError", keyErr.what()));
                    }
                }
                
                if (!pubKey) {
                    return Error("Unable to parse PEM file as either certificate or public key: " + pubKeyPath);
                }
                
                pubKeys.push_back(pubKey);
                
            } catch (const std::exception& e) {
                return Error("Unable to parse valid public key certificate from PEM file " + 
                           pubKeyPath + ": " + e.what());
            }
        }
        
        // 如果提供了文件路径但没有成功解析任何密钥，返回错误
        if (pubKeys.empty() && !pubKeyPaths.empty()) {
            return Error("No valid public keys found in the provided certificate files.");
        }
        
        utils::GetLogger().Info("Successfully ingested public keys", 
            utils::LogContext()
                .With("keyCount", std::to_string(pubKeys.size())));
        
        return pubKeys;
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to ingest public keys: ") + e.what());
    }
}

// checkAllPaths函数实现 - 对应Go版本的checkAllPaths函数
// 检查路径列表中是否包含空字符串，如果有则表示要添加所有路径
void checkAllPaths(std::vector<std::string>& paths, bool& allPaths) {
    // 检查是否有空路径 (对应Go的if path == "")
    for (const auto& path : paths) {
        if (path.empty()) {
            allPaths = true;
            break;
        }
    }
    
    // 如果用户传递了--all-paths（或在--paths中给出了""路径），给出""路径
    // (对应Go的if d.allPaths { d.paths = []string{""} })
    if (allPaths) {
        paths.clear();
        paths.push_back("");
    }
}

int main(int argc, char** argv) {
    CLI::App app{"Notary - A tool for signing and managing content"};
    
    // 全局选项
    std::string configFile;
    std::string trustDir;
    std::string serverURL;
    std::string keyID;
    bool debug = false;
    
    app.add_option("-c,--config", configFile, "Configuration file path");
    app.add_option("-d,--trust-dir", trustDir, "Trust directory path");
    app.add_option("-s,--server", serverURL, "Remote trust server URL");
    app.add_flag("-D,--debug", debug, "Enable debug output");
    
    // init 命令
    auto init = app.add_subcommand("init", "Initialize a new trusted collection");
    std::string gun;
    std::string rootKey;
    std::string rootCert;
    bool autoPublish = false;
    
    init->add_option("gun", gun, "Globally Unique Name")->required();
    init->add_option("--rootkey", rootKey, "Root key file path");
    init->add_option("--rootcert", rootCert, "Root certificate file path");
    init->add_flag("-p,--publish", autoPublish, "Auto publish after initialization");
    
    init->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Initializing GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 导入根密钥
            std::vector<std::string> rootKeyIDs;
            auto keyErr = importRootKey(rootKey, rootKeyIDs);
            if (!keyErr.ok()) {
                utils::GetLogger().Error("Error importing root key: " + keyErr.what());
                return;
            }
            
            // 4. 导入根证书
            std::vector<std::string> rootCerts;
            auto certErr = importRootCert(rootCert, rootCerts);
            if (!certErr.ok()) {
                utils::GetLogger().Error("Error importing root certificate: " + certErr.what());
                return;
            }
            
            // 5. 如果指定了证书但没有指定密钥，清空密钥ID列表以允许从密钥存储中搜索密钥
            if (rootKey.empty() && !rootCert.empty()) {
                rootKeyIDs.clear();
            }
            
            // 6. 初始化仓库
            auto initErr = repo.Initialize(rootKeyIDs);
            if (!initErr.ok()) {
                utils::GetLogger().Error("Error initializing repository: " + initErr.what());
                return;
            }
            
            utils::GetLogger().Info("Successfully initialized trust data for " + gun, utils::LogContext()
                .With("trustDir", trustDir));
            
            // 7. 可能自动发布
            auto pubErr = maybeAutoPublish(autoPublish, gun, serverURL, repo);
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // add 命令 - 修改参数处理方式
    auto add = app.add_subcommand("add", "Adds the file as a target to the trusted collection");
    std::vector<std::string> roles;
    std::string customPath;
    std::string targetName, targetPath; // 新增变量直接接收参数
    
    add->add_option("gun", gun, "Globally Unique Name")->required();
    add->add_option("target_name", targetName, "Target name")->required();
    add->add_option("target_path", targetPath, "Path to target data")->required();
    add->add_option("-r,--roles", roles, "Delegation roles to add this target to");
    add->add_option("--custom", customPath, "Path to the file containing custom data for this target");
    add->add_flag("-p,--publish", autoPublish, "Auto publish after adding target");
    
    add->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Adding target to GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 加载自定义数据（如果有）
            std::vector<uint8_t> customData;
            if (!customPath.empty()) {
                auto customResult = getTargetCustom(customPath);
                if (!customResult.ok()) {
                    utils::GetLogger().Error("Error loading custom data: " + customResult.error().what());
                    return;
                }
                customData = customResult.value();
            }
            
            // 4. 创建目标对象
            auto targetResult = Repository::NewTarget(targetName, targetPath, customData);
            if (!targetResult.ok()) {
                utils::GetLogger().Error("Error creating target: " + targetResult.error().what());
                return;
            }
            
            // 5. 添加目标
            auto addErr = repo.AddTarget(targetResult.value(), roles);
            if (!addErr.ok()) {
                utils::GetLogger().Error("Error adding target: " + addErr.what());
                return;
            }
            
            utils::GetLogger().Info("Addition of target \"" + targetName + "\" to repository \"" + gun + "\" staged for next publish.");
            
            // 6. 可能自动发布
            auto pubErr = maybeAutoPublish(autoPublish, gun, serverURL, repo);
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // remove 命令 - 从可信集合中移除目标 (对应Go的RemoveTarget)
    auto remove = app.add_subcommand("remove", "Removes a target from the trusted collection");
    std::vector<std::string> removeRoles;
    std::string removeTargetName;
    
    remove->add_option("gun", gun, "Globally Unique Name")->required();
    remove->add_option("target_name", removeTargetName, "Target name to remove")->required();
    remove->add_option("-r,--roles", removeRoles, "Delegation roles to remove this target from");
    remove->add_flag("-p,--publish", autoPublish, "Auto publish after removing target");
    
    remove->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Removing target from GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 移除目标 (对应Go的RemoveTarget调用)
            auto removeErr = repo.RemoveTarget(removeTargetName, removeRoles);
            if (!removeErr.ok()) {
                utils::GetLogger().Error("Error removing target: " + removeErr.what());
                return;
            }
            
            utils::GetLogger().Info("Removal of target \"" + removeTargetName + "\" from repository \"" + gun + "\" staged for next publish.");
            
            // 4. 可能自动发布
            auto pubErr = maybeAutoPublish(autoPublish, gun, serverURL, repo);
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // publish 命令
    auto publish = app.add_subcommand("publish", "Publishes staged changes");
    
    publish->add_option("gun", gun, "Globally Unique Name")->required();
    
    publish->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Publishing changes for GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 发布更改
            auto pubErr = repo.Publish();
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
            utils::GetLogger().Info("Successfully published changes for " + gun);
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // verify 命令
    auto verify = app.add_subcommand("verify", "Verifies the content of a target against its trusted metadata");
    std::string targetFilePath; // 要验证的文件路径
    
    verify->add_option("gun", gun, "Globally Unique Name")->required();
    verify->add_option("target_name", targetName, "Target name to verify")->required();
    verify->add_option("target_file", targetFilePath, "Path to the target file to verify")->required();
    
    verify->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Verifying target in GUN: " + gun, utils::LogContext()
                    .With("target", targetName)
                    .With("file", targetFilePath));
            }
            
            // 2. 检查目标文件是否存在
            if (!fs::exists(targetFilePath)) {
                utils::GetLogger().Error("Target file not found: " + targetFilePath);
                return;
            }
            
            // 3. 读取目标文件内容作为payload
            std::vector<uint8_t> payload;
            try {
                std::ifstream file(targetFilePath, std::ios::binary | std::ios::ate);
                if (!file) {
                    utils::GetLogger().Error("Failed to open target file: " + targetFilePath);
                    return;
                }
                
                auto size = file.tellg();
                file.seekg(0, std::ios::beg);
                
                payload.resize(size);
                if (!file.read(reinterpret_cast<char*>(payload.data()), size)) {
                    utils::GetLogger().Error("Failed to read target file: " + targetFilePath);
                    return;
                }
            } catch (const std::exception& e) {
                utils::GetLogger().Error("Error reading target file: " + std::string(e.what()));
                return;
            }
            
            // 4. 创建仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 5. 通过名称获取目标信息
            auto targetResult = repo.GetTargetByName(targetName);
            if (!targetResult.ok()) {
                utils::GetLogger().Error("Error retrieving target by name: " + targetResult.error().what());
                return;
            }
            
            auto target = targetResult.value();
            
            // 6. 验证哈希值
            auto hashErr = utils::CheckHashes(payload, targetName, target.hashes);
            if (!hashErr.ok()) {
                utils::GetLogger().Error("Data not present in the trusted collection: " + hashErr.what());
                return;
            }
            
            // 7. 验证成功
            utils::GetLogger().Info("Successfully verified target \"" + targetName + "\" in repository \"" + gun + "\"");
            utils::GetLogger().Info("Target file matches trusted metadata", utils::LogContext()
                .With("file", targetFilePath)
                .With("size", std::to_string(target.length))
                .With("hash_algorithms", std::to_string(target.hashes.size())));
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // list 命令 - 列出远程可信集合中的所有目标 (对应Go的tufList)
    auto list = app.add_subcommand("list", "Lists targets in the remote trusted collection");
    std::vector<std::string> listRoles;  // 用于指定要列出的角色
    
    list->add_option("gun", gun, "Globally Unique Name")->required();
    list->add_option("-r,--roles", listRoles, "Delegation roles to list targets from");
    
    list->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Listing targets for GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建仓库实例 (对应Go的ConfigureRepo和fact(gun))
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 转换角色名称字符串为RoleName枚举 (对应Go的data.NewRoleList(t.roles))
            std::vector<std::string> roleNames;
            for (const auto& roleStr : listRoles) {
                // 检查角色字符串是否有效
                if (roleStr == ROOT_ROLE || roleStr == TARGETS_ROLE || roleStr == SNAPSHOT_ROLE || roleStr == TIMESTAMP_ROLE) {
                    roleNames.push_back(roleStr);
                } else {
                    utils::GetLogger().Warn("Ignoring invalid role: " + roleStr);
                }
            }
            
            // 4. 获取远程签名目标列表 (对应Go的nRepo.ListTargets)
            auto targetListResult = repo.ListTargets(roleNames);
            if (!targetListResult.ok()) {
                utils::GetLogger().Error("Error listing targets: " + targetListResult.error().what());
                return;
            }
            
            auto targetList = targetListResult.value();
            
            // 5. 美化打印目标列表 (对应Go的prettyPrintTargets)
            prettyPrintTargets(targetList);
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // status 命令 - 显示本地可信集合的未发布更改状态 (对应Go的changelist相关功能)
    auto status = app.add_subcommand("status", "Displays unpublished changes to the trusted collection");
    
    status->add_option("gun", gun, "Globally Unique Name")->required();
    
    status->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Checking status for GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 获取changelist
            auto changelist = repo.GetChangelistPublic();
            if (!changelist) {
                utils::GetLogger().Error("Failed to get changelist");
                return;
            }
            
            // 4. 获取所有未发布的更改
            auto changes = changelist->List();
            
            // 5. 显示更改状态
            prettyPrintChanges(changes);
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // reset 命令 - 重置本地可信集合的未发布更改 (对应Go的reset相关功能)
    auto reset = app.add_subcommand("reset", "Resets unpublished changes to the trusted collection");
    bool resetAll = false;
    std::vector<int> resetNumbers;
    
    reset->add_option("gun", gun, "Globally Unique Name")->required();
    reset->add_flag("--all", resetAll, "Reset all unpublished changes");
    reset->add_option("-n,--number", resetNumbers, "Reset specific change numbers");
    
    reset->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Resetting changes for GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建仓库实例
            Repository repo(gun, trustDir, serverURL);
            
            // 3. 获取changelist
            auto changelist = repo.GetChangelistPublic();
            if (!changelist) {
                utils::GetLogger().Error("Failed to get changelist");
                return;
            }
            
            // 4. 执行重置操作
            Error resetErr;
            if (resetAll) {
                // 重置所有更改 (对应Go的Clear方法)
                resetErr = changelist->Clear("");
                if (!resetErr.ok()) {
                    utils::GetLogger().Error("Error resetting all changes: " + resetErr.what());
                    return;
                }
                utils::GetLogger().Info("Successfully reset all unpublished changes for " + gun);
            } else if (!resetNumbers.empty()) {
                // 重置指定编号的更改 (对应Go的Remove方法)
                resetErr = changelist->Remove(resetNumbers);
                if (!resetErr.ok()) {
                    utils::GetLogger().Error("Error resetting specific changes: " + resetErr.what());
                    return;
                }
                utils::GetLogger().Info("Successfully reset selected unpublished changes for " + gun);
            } else {
                utils::GetLogger().Error("Must specify either --all or --number option");
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // delete 命令 - 删除GUN的信任数据 (对应Go的tufDeleteGUN)
    auto deleteCmd = app.add_subcommand("delete", "Deletes trust data for a repository");
    bool deleteRemote = false;
    
    deleteCmd->add_option("gun", gun, "Globally Unique Name")->required();
    deleteCmd->add_flag("--remote", deleteRemote, "Delete remote trust data as well as local");
    
    deleteCmd->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 准备删除信息文本
            std::string remoteDeleteInfo = deleteRemote ? " and remote" : "";
            
            utils::GetLogger().Info("Deleting trust data for repository " + gun);
            
            // 3. 调用Repository的静态删除方法 (对应Go的notaryclient.DeleteTrustData)
            auto deleteErr = Repository::DeleteTrustData(
                trustDir,           // baseDir
                gun,               // gun  
                serverURL,         // URL
                deleteRemote       // deleteRemote
            );
            
            if (!deleteErr.ok()) {
                utils::GetLogger().Error("Error deleting trust data: " + deleteErr.what());
                return;
            }
            
            // 4. 成功删除日志 (对应Go的成功日志)
            utils::GetLogger().Info("Successfully deleted local" + remoteDeleteInfo + " trust data for repository " + gun);
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // ======================== delegation 命令组 ========================
    auto delegation = app.add_subcommand("delegation", "Manage delegations");
    auto delegationAdd = delegation->add_subcommand("add", "Add a delegation role with public keys and paths");
    auto delegationRemove = delegation->add_subcommand("remove", "Remove delegation keys or paths");
    auto delegationList = delegation->add_subcommand("list", "List delegations for the Global Unique Name");
    auto delegationPurge = delegation->add_subcommand("purge", "Remove KeyID(s) from all delegation roles in the given GUN");
    
    // delegation add 参数定义 - 对应Go版本的delegationAdd函数参数
    std::string delegationGUN;
    std::string delegationRole;
    std::vector<std::string> delegationPubKeyPaths;
    std::vector<std::string> delegationPaths;
    bool delegationAllPaths = false;
    bool delegationAutoPublish = false;
    
    delegationAdd->add_option("gun", delegationGUN, "Globally Unique Name")->required();
    delegationAdd->add_option("role", delegationRole, "Delegation role name")->required();
    delegationAdd->add_option("pubkey_file", delegationPubKeyPaths, "Path to public key certificate file(s)")->expected(-1);
    delegationAdd->add_option("--paths", delegationPaths, "List of paths to add to this delegation");
    delegationAdd->add_flag("--all-paths", delegationAllPaths, "Add all paths to this delegation");
    delegationAdd->add_flag("-p,--publish", delegationAutoPublish, "Auto publish after adding delegation");
    
    // delegation remove 参数定义 - 对应Go版本的delegationRemove函数参数
    std::string removeGUN;
    std::string removeRole;
    std::vector<std::string> removeKeyIDs;
    std::vector<std::string> removePaths;
    bool removeAllPaths = false;
    bool removeAll = false;
    bool forceYes = false;
    bool removeAutoPublish = false;
    
    delegationRemove->add_option("gun", removeGUN, "Globally Unique Name")->required();
    delegationRemove->add_option("role", removeRole, "Delegation role name")->required();
    delegationRemove->add_option("key_id", removeKeyIDs, "Key IDs to remove from delegation")->expected(-1);
    delegationRemove->add_option("--paths", removePaths, "List of paths to remove from delegation");
    delegationRemove->add_flag("--all-paths", removeAllPaths, "Remove all paths from this delegation");
    delegationRemove->add_flag("--all", removeAll, "Remove entire delegation");
    delegationRemove->add_flag("-y,--yes", forceYes, "Answer yes to the removal question (no confirmation)");
    delegationRemove->add_flag("-p,--publish", removeAutoPublish, "Auto publish after removing delegation");
    
    // delegation list 参数定义 - 对应Go版本的delegationsList函数参数
    std::string listGUN;
    
    delegationList->add_option("gun", listGUN, "Globally Unique Name")->required();
    
    // delegation purge 参数定义 - 对应Go版本的delegationPurgeKeys函数参数
    std::string purgeGUN;
    std::vector<std::string> purgeKeyIDs;
    bool purgeAutoPublish = false;
    
    delegationPurge->add_option("gun", purgeGUN, "Globally Unique Name")->required();
    delegationPurge->add_option("--key", purgeKeyIDs, "Delegation key IDs to be removed from the GUN")->expected(-1);
    delegationPurge->add_flag("-p,--publish", purgeAutoPublish, "Auto publish after purging keys");

    // ======================== key 命令组 ========================
    auto key = app.add_subcommand("key", "Manage signing keys");
    auto keysList = key->add_subcommand("list", "List all signing keys");
    auto keyGenerate = key->add_subcommand("generate", "Generate a new signing key");
    auto keyRemove = key->add_subcommand("remove", "Remove a signing key");
    auto keyPasswd = key->add_subcommand("passwd", "Change the passphrase for a signing key");
    auto keyRotate = key->add_subcommand("rotate", "Rotate a key for a repository and role");
    auto keyInspect = key->add_subcommand("inspect", "Inspect a public key and show its key ID");
    
    // key generate 参数定义 - 对应Go版本的keysGenerate函数参数
    std::string generateAlgorithm = "ecdsa";  // 默认算法
    std::string generateRole = "root";        // 默认角色
    std::string generateOutFile;              // 输出文件路径
    
    keyGenerate->add_option("algorithm", generateAlgorithm, "Key algorithm (ecdsa)")->expected(0, 1);
    keyGenerate->add_option("-r,--role", generateRole, "Role for the key (default: root)");
    keyGenerate->add_option("-o,--output", generateOutFile, "Output file path for key (without extension)");
    
    // key rotate 参数定义 - 对应Go版本的keysRotate函数参数
    std::string rotateGUN;
    std::string rotateRole;
    bool serverManaged = false;
    std::vector<std::string> keyFiles;
    
    keyRotate->add_option("gun", rotateGUN, "Globally Unique Name of the repository")->required();
    keyRotate->add_option("role", rotateRole, "Role to rotate key for (root, targets, snapshot, timestamp)")->required();
    keyRotate->add_flag("--server-managed", serverManaged, "Use server-managed key rotation");
    keyRotate->add_option("--key-file", keyFiles, "Key file(s) to import for rotation (can be used multiple times)");
    
    // key inspect 参数定义
    std::string inspectKeyFile;
    
    keyInspect->add_option("key_file", inspectKeyFile, "Path to the public key file to inspect")->required();
    
    keyGenerate->callback([&]() {
        try {
            // 1. 验证算法参数 (对应Go版本的参数检查)
            std::transform(generateAlgorithm.begin(), generateAlgorithm.end(), 
                          generateAlgorithm.begin(), ::tolower);
            
            if (generateAlgorithm != "ecdsa") {
                utils::GetLogger().Error("Algorithm not allowed, possible values are: ECDSA");
                return;
            }
            
            // 2. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Generating key", utils::LogContext()
                    .With("algorithm", generateAlgorithm)
                    .With("role", generateRole)
                    .With("outFile", generateOutFile.empty() ? "none" : generateOutFile));
            }
            
            // 3. 如果没有输出文件，使用密钥存储 (对应Go版本的k.outFile == "")
            if (generateOutFile.empty()) {
                // 创建密码获取器和密钥存储
                auto passRetriever = passphrase::PromptRetriever();
                auto keyStores = getKeyStores(trustDir, passRetriever, true, true);
                
                if (keyStores.empty()) {
                    utils::GetLogger().Error("Failed to create key stores");
                    return;
                }
                
                // 创建CryptoService并添加密钥存储
                crypto::CryptoService cryptoService;
                for (auto& store : keyStores) {
                    cryptoService.AddKeyStore(std::shared_ptr<storage::GenericKeyStore>(std::move(store)));
                }
                
                // 生成密钥并存储到密钥存储中 (对应Go版本的cs.Create)
                auto pubKeyResult = cryptoService.Create(generateRole, "", generateAlgorithm);
                if (!pubKeyResult.ok()) {
                    utils::GetLogger().Error("Failed to create a new " + generateRole + " key: " + 
                                           pubKeyResult.error().what());
                    return;
                }
                
                auto pubKey = pubKeyResult.value();
                std::cout << "Generated new " << generateAlgorithm << " " << generateRole 
                         << " key with keyID: " << pubKey->ID() << std::endl;
                
            } else {
                // 4. 生成密钥到文件 (对应Go版本的generateKeyToFile调用)
                auto passRetriever = passphrase::PromptRetriever();
                auto generateErr = generateKeyToFile(generateRole, generateAlgorithm, passRetriever, generateOutFile);
                if (generateErr.hasError()) {
                    utils::GetLogger().Error("Failed to generate key to file: " + generateErr.what());
                    return;
                }
                
                utils::GetLogger().Info("Successfully generated key pair to files");
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    keysList->callback([&]() {
        try {
            // 1. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Using server URL: " + serverURL, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Listing keys for GUN: " + gun, utils::LogContext()
                    .With("serverURL", serverURL));
            }
            
            // 2. 创建密码获取器
             auto passRetriever = passphrase::PromptRetriever();
             
             // 3. 获取密钥存储列表
             auto keyStores = getKeyStores(trustDir, passRetriever, true, false);
             
             if (keyStores.empty()) {
                 utils::GetLogger().Error("Failed to create key stores");
                 return;
             }
             
             // 4. 美化打印密钥列表
             std::cout << std::endl;
             prettyPrintKeys(keyStores);
             std::cout << std::endl;
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    keyRemove->add_option("key_id", keyID, "Key ID to remove")->required();
    keyPasswd->add_option("key_id", keyID, "Key ID to change passphrase for")->required();
    
    keyRemove->callback([&]() {
        try {
            // 1. 验证keyID长度（对应Go的SHA256HexSize检查）
            if (keyID.length() != 64) {  // SHA256的十六进制长度是64个字符
                utils::GetLogger().Error("Invalid key ID provided: " + keyID);
                return;
            }
            
            // 2. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Removing key with ID: " + keyID, utils::LogContext()
                    .With("keyID", keyID));
            }
            
            // 3. 创建密码获取器
            auto passRetriever = passphrase::PromptRetriever();
            
            // 4. 获取密钥存储列表
            auto keyStores = getKeyStores(trustDir, passRetriever, true, false);
            
            if (keyStores.empty()) {
                utils::GetLogger().Error("Failed to create key stores");
                return;
            }
            
            // 5. 交互式删除密钥
            std::cout << std::endl;
            auto removeErr = removeKeyInteractively(keyStores, keyID, std::cin, std::cout);
            std::cout << std::endl;
            
            if (removeErr.hasError()) {
                utils::GetLogger().Error("Error removing key: " + removeErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
     
    keyPasswd->callback([&]() {
        try {
            // 1. 验证keyID长度（对应Go的SHA256HexSize检查）
            if (keyID.length() != 64) {  // SHA256的十六进制长度是64个字符
                utils::GetLogger().Error("Invalid key ID provided: " + keyID);
                return;
            }
            
            // 2. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Using trust directory: " + trustDir, utils::LogContext()
                    .With("serverURL", serverURL));
                utils::GetLogger().Info("Changing passphrase for key ID: " + keyID, utils::LogContext()
                    .With("keyID", keyID));
            }
            
            // 3. 创建密码获取器
            auto passRetriever = passphrase::PromptRetriever();
            
            // 4. 获取密钥存储列表
            auto keyStores = getKeyStores(trustDir, passRetriever, true, false);
            
            if (keyStores.empty()) {
                utils::GetLogger().Error("Failed to create key stores");
                return;
            }
            
            // 5. 在所有密钥存储中查找该密钥（对应Go的for循环查找）
            storage::GenericKeyStore* foundKeyStore = nullptr;
            std::shared_ptr<crypto::PrivateKey> privKey = nullptr;
            std::string keyRole;
            
            for (auto& store : keyStores) {
                auto keyResult = store->GetKey(keyID);
                if (keyResult.ok()) {
                    auto [foundPrivKey, foundRole] = keyResult.value();
                    foundKeyStore = store.get();
                    privKey = foundPrivKey;
                    keyRole = foundRole;
                    break;
                }
            }
            
            if (!foundKeyStore || !privKey) {
                utils::GetLogger().Error("Could not retrieve local key for key ID provided: " + keyID);
                return;
            }
            
            // 6. 获取密钥信息
            auto keyInfoResult = foundKeyStore->GetKeyInfo(keyID);
            if (!keyInfoResult.ok()) {
                utils::GetLogger().Error("Could not get key info for key ID: " + keyID);
                return;
            }
            auto keyInfo = keyInfoResult.value();
            
            // 7. 创建新的密码获取器用于更改密码（对应Go的passChangeRetriever）
            auto newPassRetriever = passphrase::PromptRetriever();
            
            // 8. 创建新的密钥存储用于重新添加密钥（这样就更改了密码）
            std::string privateDir = trustDir + "/private";
            auto addingKeyStore = storage::NewKeyFileStore(privateDir, newPassRetriever);
            if (!addingKeyStore) {
                utils::GetLogger().Error("Failed to create key store for password change");
                return;
            }
            
            // 9. 重新添加密钥，这会提示用户输入新密码
            auto addErr = addingKeyStore->AddKey(keyInfo, privKey);
            if (addErr.hasError()) {
                utils::GetLogger().Error("Failed to update key passphrase: " + addErr.what());
                return;
            }
            
            std::cout << "\nSuccessfully updated passphrase for key ID: " + keyID << std::endl;
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error: " + std::string(e.what()));
            return;
        }
    });
    
    // delegation add 命令实现 - 对应Go版本的delegationAdd函数
    delegationAdd->callback([&]() {
        try {
            // 1. 验证参数 - 必须至少有GUN和角色名，以及至少一个密钥或路径（或--all-paths标志）
            // (对应Go的if len(args) < 2 || len(args) < 3 && d.paths == nil && !d.allPaths)
            if (delegationGUN.empty() || delegationRole.empty()) {
                utils::GetLogger().Error("Must specify the Global Unique Name and the role of the delegation");
                return;
            }
            
            if (delegationPubKeyPaths.empty() && delegationPaths.empty() && !delegationAllPaths) {
                utils::GetLogger().Error("Must specify public key certificate paths and/or a list of paths to add");
                return;
            }
            
            // 2. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Adding delegation", utils::LogContext()
                    .With("gun", delegationGUN)
                    .With("role", delegationRole)
                    .With("pubKeyCount", std::to_string(delegationPubKeyPaths.size()))
                    .With("pathCount", std::to_string(delegationPaths.size()))
                    .With("allPaths", delegationAllPaths ? "true" : "false"));
            }
            
            // 3. 验证角色名称是否是有效的委托名称 (对应Go的data.IsDelegation(role))
            // 委托角色名称通常包含"/"分隔符，且不是基础角色
            if (delegationRole == ROOT_ROLE || delegationRole == TARGETS_ROLE || 
                delegationRole == SNAPSHOT_ROLE || delegationRole == TIMESTAMP_ROLE) {
                utils::GetLogger().Error("Invalid delegation name: " + delegationRole + " - cannot use base role names");
                return;
            }
            
            if (delegationRole.find('/') == std::string::npos) {
                utils::GetLogger().Error("Invalid delegation name: " + delegationRole + " - delegation names should contain '/'");
                return;
            }
            
            // 4. 读取公钥文件 (对应Go的ingestPublicKeys(args))
            std::vector<std::shared_ptr<crypto::PublicKey>> pubKeys;
            if (!delegationPubKeyPaths.empty()) {
                auto pubKeysResult = ingestPublicKeys(delegationPubKeyPaths);
                if (!pubKeysResult.ok()) {
                    utils::GetLogger().Error("Error reading public keys: " + pubKeysResult.error().what());
                    return;
                }
                pubKeys = pubKeysResult.value();
            }
            
            // 5. 处理路径选项 (对应Go的checkAllPaths(d))
            auto paths = delegationPaths;
            checkAllPaths(paths, delegationAllPaths);
            
            // 6. 创建仓库实例 (对应Go的notaryclient.NewFileCachedRepository)
            // 不执行在线操作，因此transport参数应为nil
            Repository repo(delegationGUN, trustDir, serverURL);
            
            // 7. 添加委托到仓库 (对应Go的nRepo.AddDelegation(role, pubKeys, d.paths))
            auto addErr = repo.AddDelegation(delegationRole, pubKeys, paths);
            if (addErr.hasError()) {
                utils::GetLogger().Error("Failed to create delegation: " + addErr.what());
                return;
            }
            
            // 8. 生成密钥ID列表用于更好的CLI打印 (对应Go的pubKeyID, err := utils.CanonicalKeyID(pubKey))
            std::vector<std::string> pubKeyIDs;
            for (const auto& pubKey : pubKeys) {
                pubKeyIDs.push_back(pubKey->ID());
            }
            
            // 9. 输出成功信息 (对应Go的cmd.Printf("Addition of delegation role..."))
            std::cout << std::endl;
            
            std::string addingItems = "";
            if (!pubKeyIDs.empty()) {
                addingItems += "with keys [";
                for (size_t i = 0; i < pubKeyIDs.size(); ++i) {
                    if (i > 0) addingItems += ", ";
                    addingItems += pubKeyIDs[i];
                }
                addingItems += "], ";
            }
            
            if (!paths.empty() || delegationAllPaths) {
                addingItems += "with paths [";
                for (size_t i = 0; i < paths.size(); ++i) {
                    if (i > 0) addingItems += ", ";
                    addingItems += paths[i];
                }
                addingItems += "], ";
            }
            
            std::cout << "Addition of delegation role " << delegationRole << " " 
                     << addingItems << "to repository \"" << delegationGUN 
                     << "\" staged for next publish." << std::endl;
            std::cout << std::endl;
            
            // 10. 可能自动发布 (对应Go的maybeAutoPublish)
            auto pubErr = maybeAutoPublish(delegationAutoPublish, delegationGUN, serverURL, repo);
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error adding delegation: " + std::string(e.what()));
            return;
        }
    });
    
    // delegation remove 命令实现 - 对应Go版本的delegationRemove函数
    delegationRemove->callback([&]() {
        try {
            // 1. 验证参数 - 至少需要GUN和角色名 (对应Go的len(args) < 2检查)
            if (removeGUN.empty() || removeRole.empty()) {
                utils::GetLogger().Error("Must specify the Global Unique Name and the role of the delegation along with optional keyIDs and/or a list of paths to remove");
                return;
            }
            
            // 2. 验证角色名称是否是有效的委托名称 (对应Go的data.IsDelegation(role))
            if (removeRole == ROOT_ROLE || removeRole == TARGETS_ROLE || 
                removeRole == SNAPSHOT_ROLE || removeRole == TIMESTAMP_ROLE) {
                utils::GetLogger().Error("Invalid delegation name: " + removeRole + " - cannot use base role names");
                return;
            }
            
            if (removeRole.find('/') == std::string::npos) {
                utils::GetLogger().Error("Invalid delegation name: " + removeRole + " - delegation names should contain '/'");
                return;
            }
            
            // 3. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            // 4. 检查参数逻辑 - 如果没有指定密钥ID和路径，且没有--all-paths，则表示要删除整个委托
            // (对应Go的if len(args) == 2 && d.paths == nil && !d.allPaths)
            if (removeKeyIDs.empty() && removePaths.empty() && !removeAllPaths) {
                removeAll = true;
            }
            
            // 5. 如果用户传递了--all-paths，不使用任何传入的--paths
            // (对应Go的if d.allPaths { d.paths = nil })
            if (removeAllPaths) {
                removePaths.clear();
            }
            
            if (debug) {
                utils::GetLogger().Info("Removing delegation", utils::LogContext()
                    .With("gun", removeGUN)
                    .With("role", removeRole)
                    .With("keyIDCount", std::to_string(removeKeyIDs.size()))
                    .With("pathCount", std::to_string(removePaths.size()))
                    .With("allPaths", removeAllPaths ? "true" : "false")
                    .With("removeAll", removeAll ? "true" : "false"));
            }
            
            // 6. 创建仓库实例 (对应Go的notaryclient.NewFileCachedRepository)
            Repository repo(removeGUN, trustDir, serverURL);
            
            Error removeErr;
            
            // 7. 根据不同的删除类型执行相应操作
            if (removeAll) {
                // 删除整个委托 (对应Go的nRepo.RemoveDelegationRole(role))
                
                // 请求确认 (对应Go的askConfirm逻辑)
                std::cout << "\nAre you sure you want to remove all data for this delegation? (yes/no)" << std::endl;
                if (!forceYes) {
                    if (!askConfirm(std::cin)) {
                        std::cout << "Aborting action." << std::endl;
                        return;
                    }
                } else {
                    std::cout << "Confirmed `yes` from flag" << std::endl;
                }
                
                // 删除整个委托
                removeErr = repo.RemoveDelegationRole(removeRole);
                if (!removeErr.ok()) {
                    utils::GetLogger().Error("Failed to remove delegation: " + removeErr.what());
                    return;
                }
                
            } else {
                // 部分删除 - 清除路径或移除密钥/路径
                if (removeAllPaths) {
                    // 清除所有路径 (对应Go的nRepo.ClearDelegationPaths(role))
                    removeErr = repo.ClearDelegationPaths(removeRole);
                    if (!removeErr.ok()) {
                        utils::GetLogger().Error("Failed to clear delegation paths: " + removeErr.what());
                        return;
                    }
                }
                
                // 移除任何传入的密钥或路径 (对应Go的nRepo.RemoveDelegationKeysAndPaths)
                if (!removeKeyIDs.empty() || !removePaths.empty()) {
                    removeErr = repo.RemoveDelegationKeysAndPaths(removeRole, removeKeyIDs, removePaths);
                    if (!removeErr.ok()) {
                        utils::GetLogger().Error("Failed to remove delegation keys and paths: " + removeErr.what());
                        return;
                    }
                }
            }
            
            // 8. 输出结果信息 (对应Go的delegationRemoveOutput)
            std::cout << std::endl;
            if (removeAll) {
                std::cout << "Forced removal (including all keys and paths) of delegation role " 
                         << removeRole << " to repository \"" << removeGUN 
                         << "\" staged for next publish." << std::endl;
            } else {
                std::string removingItems = "";
                
                if (!removeKeyIDs.empty()) {
                    removingItems += "with keys [";
                    for (size_t i = 0; i < removeKeyIDs.size(); ++i) {
                        if (i > 0) removingItems += ", ";
                        removingItems += removeKeyIDs[i];
                    }
                    removingItems += "], ";
                }
                
                if (removeAllPaths) {
                    removingItems += "with all paths, ";
                }
                
                if (!removePaths.empty()) {
                    removingItems += "with paths [";
                    for (size_t i = 0; i < removePaths.size(); ++i) {
                        if (i > 0) removingItems += ", ";
                        removingItems += removePaths[i];
                    }
                    removingItems += "], ";
                }
                
                std::cout << "Removal of delegation role " << removeRole << " " 
                         << removingItems << "to repository \"" << removeGUN 
                         << "\" staged for next publish." << std::endl;
            }
            std::cout << std::endl;
            
            // 9. 可能自动发布 (对应Go的maybeAutoPublish)
            auto pubErr = maybeAutoPublish(removeAutoPublish, removeGUN, serverURL, repo);
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error removing delegation: " + std::string(e.what()));
            return;
        }
    });
    
    // delegation list 命令实现 - 对应Go版本的delegationsList函数
    delegationList->callback([&]() {
        try {
            // 1. 验证参数 - 需要提供GUN (对应Go的len(args) != 1检查)
            if (listGUN.empty()) {
                utils::GetLogger().Error("Please provide a Global Unique Name as an argument to list");
                return;
            }
            
            // 2. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Listing delegations", utils::LogContext()
                    .With("gun", listGUN)
                    .With("trustDir", trustDir)
                    .With("serverURL", serverURL));
            }
            
            // 3. 创建仓库实例 (对应Go的notaryclient.NewFileCachedRepository)
            // 使用transport来获取最新状态
            Repository repo(listGUN, trustDir, serverURL);
            
            // 4. 获取委托角色列表 (对应Go的nRepo.GetDelegationRoles())
            auto delegationRolesResult = repo.GetDelegationRoles();
            if (!delegationRolesResult.ok()) {
                utils::GetLogger().Error("Error retrieving delegation roles for repository " + listGUN + ": " + 
                                       delegationRolesResult.error().what());
                return;
            }
            
            auto delegationRoles = delegationRolesResult.value();
            
            // 5. 美化打印委托角色 (对应Go的prettyPrintRoles(delegationRoles, cmd.OutOrStdout(), "delegations"))
            prettyPrintRoles(delegationRoles, "delegations");
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error listing delegations: " + std::string(e.what()));
            return;
        }
    });
    
    // delegation purge 命令实现 - 对应Go版本的delegationPurgeKeys函数
    delegationPurge->callback([&]() {
        try {
            // 1. 验证参数 - 需要提供GUN (对应Go的len(args) != 1检查)
            if (purgeGUN.empty()) {
                utils::GetLogger().Error("Please provide a single Global Unique Name as an argument to remove");
                return;
            }
            
            // 2. 验证至少提供一个密钥ID (对应Go的len(d.keyIDs) == 0检查)
            if (purgeKeyIDs.empty()) {
                utils::GetLogger().Error("Please provide at least one key ID to be removed using the --key flag");
                return;
            }
            
            // 3. 加载配置
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Purging delegation keys", utils::LogContext()
                    .With("gun", purgeGUN)
                    .With("keyIDs", utils::vectorToString(purgeKeyIDs))
                    .With("trustDir", trustDir)
                    .With("serverURL", serverURL));
            }
            
            // 4. 创建仓库实例 (对应Go的notaryclient.NewFileCachedRepository)
            Repository repo(purgeGUN, trustDir, serverURL);
            
            // 5. 从所有委托中移除密钥 (对应Go的nRepo.RemoveDelegationKeys("targets/*", d.keyIDs))
            // 使用通配符"targets/*"表示从所有委托角色中移除
            auto removeErr = repo.RemoveDelegationKeys("targets/*", purgeKeyIDs);
            if (!removeErr.ok()) {
                utils::GetLogger().Error("Failed to remove keys from delegations: " + removeErr.what());
                return;
            }
            
            // 6. 输出成功信息 (对应Go的fmt.Printf)
            std::cout << std::endl;
            std::cout << "Removal of the following keys from all delegations in " << purgeGUN 
                     << " staged for next publish:" << std::endl;
            for (const auto& keyID : purgeKeyIDs) {
                std::cout << "\t- " << keyID << std::endl;
            }
            std::cout << std::endl;
            
            // 7. 可能自动发布 (对应Go的maybeAutoPublish)
            auto pubErr = maybeAutoPublish(purgeAutoPublish, purgeGUN, serverURL, repo);
            if (!pubErr.ok()) {
                utils::GetLogger().Error("Error publishing changes: " + pubErr.what());
                return;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error purging delegation keys: " + std::string(e.what()));
            return;
        }
    });

    // key rotate 命令实现 - 对应Go版本的keysRotate函数
    keyRotate->callback([&]() {
        try {
            // 1. 验证参数 (对应Go的len(args) < 2检查)
            if (rotateGUN.empty() || rotateRole.empty()) {
                utils::GetLogger().Error("Must specify a GUN and a key role to rotate");
                return;
            }
            
            // 2. 验证角色名称 (对应Go的rotateKeyRole := data.RoleName(args[1]))
            if (rotateRole != "root" && rotateRole != "targets" && 
                rotateRole != "snapshot" && rotateRole != "timestamp") {
                utils::GetLogger().Error("Invalid role name: " + rotateRole);
                utils::GetLogger().Info("Valid roles are: root, targets, snapshot, timestamp");
                return;
            }
            
            std::string rotateKeyRole = rotateRole;
            
            // 3. 加载配置 (对应Go的config, err := k.configGetter())
            auto configErr = loadConfig(configFile, trustDir, serverURL);
            if (!configErr.ok()) {
                utils::GetLogger().Error("Error loading configuration: " + configErr.what());
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Starting key rotation", utils::LogContext()
                    .With("gun", rotateGUN)
                    .With("role", rotateRole)
                    .With("serverManaged", serverManaged ? "true" : "false")
                    .With("keyFileCount", std::to_string(keyFiles.size())));
            }
            
            // 4. 创建仓库 (对应Go的notaryclient.NewFileCachedRepository)
            Repository repo(rotateGUN, trustDir, serverURL);
            
            std::vector<std::string> keyList;
            
            // 5. 处理密钥文件导入 (对应Go的for _, keyFile := range k.rotateKeyFiles)
            for (const auto& keyFile : keyFiles) {
                utils::GetLogger().Info("Importing key file", utils::LogContext()
                    .With("keyFile", keyFile)
                    .With("role", rotateRole));
                
                // TODO: 实现readKey函数来读取密钥文件
                // 这需要解析PEM格式的密钥文件并验证角色
                // auto privKey = readKey(rotateKeyRole, keyFile, passRetriever);
                // auto err = repo.GetCryptoService()->AddKey(rotateKeyRole, rotateGUN, privKey);
                // if (!err.ok()) {
                //     utils::GetLogger().Error("Error importing key: " + err.what());
                //     return;
                // }
                // keyList.push_back(privKey->ID());
                
                utils::GetLogger().Warn("Key file import functionality not yet fully implemented");
                utils::GetLogger().Info("Skipping key file: " + keyFile);
            }
            
            // 6. 根角色轮转确认 (对应Go的if rotateKeyRole == data.CanonicalRootRole)
            if (rotateKeyRole == ROOT_ROLE) {
                std::cout << "Warning: you are about to rotate your root key.\n\n";
                std::cout << "You must use your old key to sign this root rotation.\n";
                std::cout << "Are you sure you want to proceed?  (yes/no)  ";
                
                if (!askConfirm(std::cin)) {
                    std::cout << "\nAborting action." << std::endl;
                    return;
                }
            }
            
            // 7. 执行密钥轮转 (对应Go的nRepo.RotateKey(rotateKeyRole, k.rotateKeyServerManaged, keyList))
            utils::GetLogger().Info("Executing key rotation", utils::LogContext()
                .With("gun", rotateGUN)
                .With("role", rotateRole)
                .With("serverManaged", serverManaged ? "true" : "false"));
            
            auto rotateErr = repo.RotateKey(rotateKeyRole, serverManaged, keyList);
            if (!rotateErr.ok()) {
                utils::GetLogger().Error("Key rotation failed: " + rotateErr.what());
                return;
            }
            
            // 8. 成功消息 (对应Go的cmd.Printf("Successfully rotated %s key for repository %s\n", rotateKeyRole, gun))
            std::cout << "Successfully rotated " << rotateRole << " key for repository " << rotateGUN << std::endl;
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error during key rotation: " + std::string(e.what()));
            return;
        }
    });
    
    // key inspect 命令实现
    keyInspect->callback([&]() {
        try {
            // 1. 验证文件是否存在
            if (!fs::exists(inspectKeyFile)) {
                utils::GetLogger().Error("Public key file not found: " + inspectKeyFile);
                return;
            }
            
            if (debug) {
                utils::GetLogger().Info("Inspecting public key file: " + inspectKeyFile);
            }
            
            // 2. 读取并解析公钥文件
            auto pubKeysResult = ingestPublicKeys({inspectKeyFile});
            if (!pubKeysResult.ok()) {
                utils::GetLogger().Error("Error reading public key: " + pubKeysResult.error().what());
                return;
            }
            
            auto pubKeys = pubKeysResult.value();
            if (pubKeys.empty()) {
                utils::GetLogger().Error("No valid public key found in file: " + inspectKeyFile);
                return;
            }
            
            // 3. 显示密钥信息
            for (const auto& pubKey : pubKeys) {
                std::cout << std::endl;
                std::cout << "Key file: " << inspectKeyFile << std::endl;
                std::cout << "Key ID: " << pubKey->ID() << std::endl;
                std::cout << "Algorithm: " << pubKey->Algorithm() << std::endl;
                std::cout << std::endl;
            }
            
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error inspecting key: " + std::string(e.what()));
            return;
        }
    });
    
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    return 0;
} 