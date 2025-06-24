#include <iostream>
#include <fstream>
#include <CLI/CLI.hpp>
#include "notary/client/repository.hpp"
#include "notary/storage/keystore.hpp"
#include "notary/passRetriever/passRetriever.hpp"
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <algorithm>

using namespace notary;

// 使用标准filesystem命名空间
namespace fs = std::filesystem;

// 密钥信息结构（用于排序和显示）
struct KeyDisplayInfo {
    std::string gun;       // 仓库名称
    RoleName role;         // 密钥角色
    std::string keyID;     // 密钥ID
    std::string location;  // 密钥存储位置
    
    KeyDisplayInfo(const std::string& g, RoleName r, const std::string& id, const std::string& loc)
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
        if (a.role == RoleName::RootRole) {
            return true;
        }
        if (b.role == RoleName::RootRole) {
            return false;
        }
        // 其他角色按字符串顺序排序
    }
    
    // 排序顺序：GUN, role, keyID, location
    std::vector<std::string> orderedA = {
        a.gun, 
        roleToString(a.role), 
        a.keyID, 
        a.location
    };
    std::vector<std::string> orderedB = {
        b.gun, 
        roleToString(b.role), 
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
                  << std::setw(15) << roleToString(keyInfo.role)
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
                foundKeys.emplace_back(fullKeyID, roleToString(keyInfo.role), 
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
        maxRoleWidth = std::max(maxRoleWidth, roleToString(targetWithRole.role).length());
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
                  << std::setw(maxRoleWidth + 2) << roleToString(targetWithRole.role)
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

// 加载自定义数据
Result<std::vector<uint8_t>> getTargetCustom(const std::string& customPath) {
    if (customPath.empty()) {
        return std::vector<uint8_t>();
    }
    
    try {
        // 检查文件是否存在
        if (!fs::exists(customPath)) {
            return Error(std::string("Custom data file not found: ") + customPath);
        }
        
        // 读取文件内容
        std::ifstream file(customPath, std::ios::binary | std::ios::ate);
        if (!file) {
            return Error(std::string("Failed to open custom data file: ") + customPath);
        }
        
        // 获取文件大小
        auto size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // 读取文件内容
        std::vector<uint8_t> customData(size);
        if (!file.read(reinterpret_cast<char*>(customData.data()), size)) {
            return Error(std::string("Failed to read custom data file: ") + customPath);
        }
        
        return customData;
    } catch (const std::exception& e) {
        return Error(std::string("Failed to load custom data: ") + e.what());
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
            std::vector<RoleName> roleNames;
            for (const auto& roleStr : listRoles) {
                // 检查角色字符串是否有效
                if (roleStr == ROOT_ROLE || roleStr == TARGETS_ROLE || roleStr == SNAPSHOT_ROLE || roleStr == TIMESTAMP_ROLE) {
                    auto roleName = stringToRole(roleStr);
                    roleNames.push_back(roleName);
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
    
         // key 命令组
     auto key = app.add_subcommand("key", "Manage signing keys");
     auto keysList = key->add_subcommand("list", "List all signing keys");
     auto keyRemove = key->add_subcommand("remove", "Remove a signing key");
    
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
    
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    return 0;
} 