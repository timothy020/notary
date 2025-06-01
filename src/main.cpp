#include <iostream>
#include <fstream>
#include <CLI/CLI.hpp>
#include "notary/repository.hpp"
#include <filesystem>

using namespace notary;

// 使用标准filesystem命名空间
namespace fs = std::filesystem;

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
    std::string password;
    bool autoPublish = false;
    
    init->add_option("gun", gun, "Globally Unique Name")->required();
    init->add_option("--rootkey", rootKey, "Root key file path");
    init->add_option("--rootcert", rootCert, "Root certificate file path");
    init->add_option("--password,--passphrase", password, "Password for key encryption");
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
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                utils::GetLogger().Warn("Using default password. Please change it for production use.");
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(gun, trustDir, serverURL);
            repo.SetPassphrase(password); // 设置密码
            
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
    add->add_option("--password,--passphrase", password, "Password for key encryption");
    
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
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                utils::GetLogger().Warn("Using default password. Please change it for production use.");
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(gun, trustDir, serverURL);
            repo.SetPassphrase(password); // 设置密码
            
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
    publish->add_option("--password,--passphrase", password, "Password for key encryption");
    
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
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                utils::GetLogger().Warn("Using default password. Please change it for production use.");
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(gun, trustDir, serverURL);
            repo.SetPassphrase(password); // 设置密码
            
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
    verify->add_option("--password,--passphrase", password, "Password for key encryption");
    
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
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                utils::GetLogger().Warn("Using default password. Please change it for production use.");
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
            repo.SetPassphrase(password);
            
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
    
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    return 0;
} 