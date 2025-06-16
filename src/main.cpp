#include <iostream>
#include <fstream>
#include <CLI/CLI.hpp>
#include "notary/repository.hpp"
#include <filesystem>
#include <iomanip>
#include <sstream>

using namespace notary;

// 使用标准filesystem命名空间
namespace fs = std::filesystem;

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
    
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    return 0;
} 