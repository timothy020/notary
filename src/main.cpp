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
        trustDir = fs::current_path().string() + "/trust";
    }
    
    if (serverURL.empty()) {
        serverURL = "https://localhost:4443";
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
    
    std::cout << "Publishing changes to " << gun << std::endl;
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
                std::cerr << "Error loading configuration: " << configErr.what() << std::endl;
                return;
            }
            
            if (debug) {
                std::cout << "Using trust directory: " << trustDir << std::endl;
                std::cout << "Using server URL: " << serverURL << std::endl;
                std::cout << "Initializing GUN: " << gun << std::endl;
            }
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                std::cout << "Warning: Using default password. Please change it for production use." << std::endl;
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(trustDir, serverURL);
            repo.SetGUN(gun);
            repo.SetPassphrase(password); // 设置密码
            
            // 3. 导入根密钥
            std::vector<std::string> rootKeyIDs;
            auto keyErr = importRootKey(rootKey, rootKeyIDs);
            if (!keyErr.ok()) {
                std::cerr << "Error importing root key: " << keyErr.what() << std::endl;
                return;
            }
            
            // 4. 导入根证书
            std::vector<std::string> rootCerts;
            auto certErr = importRootCert(rootCert, rootCerts);
            if (!certErr.ok()) {
                std::cerr << "Error importing root certificate: " << certErr.what() << std::endl;
                return;
            }
            
            // 5. 如果指定了证书但没有指定密钥，清空密钥ID列表以允许从密钥存储中搜索密钥
            if (rootKey.empty() && !rootCert.empty()) {
                rootKeyIDs.clear();
            }
            
            // 6. 初始化仓库
            auto initErr = repo.Initialize(rootKeyIDs);
            if (!initErr.ok()) {
                std::cerr << "Error initializing repository: " << initErr.what() << std::endl;
                return;
            }
            
            std::cout << "Successfully initialized trust data for " << gun << std::endl;
            std::cout << "Created key files and metadata in: " << trustDir << std::endl;
            
            // 7. 可能自动发布
            auto pubErr = maybeAutoPublish(autoPublish, gun, serverURL, repo);
            if (!pubErr.ok()) {
                std::cerr << "Error publishing changes: " << pubErr.what() << std::endl;
                return;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
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
                std::cerr << "Error loading configuration: " << configErr.what() << std::endl;
                return;
            }
            
            if (debug) {
                std::cout << "Using trust directory: " << trustDir << std::endl;
                std::cout << "Using server URL: " << serverURL << std::endl;
                std::cout << "Adding target to GUN: " << gun << std::endl;
            }
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                std::cout << "Warning: Using default password. Please change it for production use." << std::endl;
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(trustDir, serverURL);
            repo.SetGUN(gun);
            repo.SetPassphrase(password); // 设置密码
            
            // 3. 加载自定义数据（如果有）
            std::vector<uint8_t> customData;
            if (!customPath.empty()) {
                auto customResult = getTargetCustom(customPath);
                if (!customResult.ok()) {
                    std::cerr << "Error loading custom data: " << customResult.error().what() << std::endl;
                    return;
                }
                customData = customResult.value();
            }
            
            // 4. 创建目标对象
            auto targetResult = Repository::NewTarget(targetName, targetPath, customData);
            if (!targetResult.ok()) {
                std::cerr << "Error creating target: " << targetResult.error().what() << std::endl;
                return;
            }
            
            // 5. 添加目标
            auto addErr = repo.AddTarget(targetResult.value(), roles);
            if (!addErr.ok()) {
                std::cerr << "Error adding target: " << addErr.what() << std::endl;
                return;
            }
            
            std::cout << "Addition of target \"" << targetName << "\" to repository \"" 
                      << gun << "\" staged for next publish." << std::endl;
            
            // 6. 可能自动发布
            auto pubErr = maybeAutoPublish(autoPublish, gun, serverURL, repo);
            if (!pubErr.ok()) {
                std::cerr << "Error publishing changes: " << pubErr.what() << std::endl;
                return;
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
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
                std::cerr << "Error loading configuration: " << configErr.what() << std::endl;
                return;
            }
            
            if (debug) {
                std::cout << "Using trust directory: " << trustDir << std::endl;
                std::cout << "Using server URL: " << serverURL << std::endl;
                std::cout << "Publishing changes for GUN: " << gun << std::endl;
            }
            
            // 设置默认密码（如果未提供）
            if (password.empty()) {
                password = "changeme";  // 默认密码
                std::cout << "Warning: Using default password. Please change it for production use." << std::endl;
            }
            
            // 2. 创建仓库工厂并获取仓库实例
            Repository repo(trustDir, serverURL);
            repo.SetGUN(gun);
            repo.SetPassphrase(password); // 设置密码
            
            // 3. 发布更改
            auto pubErr = repo.Publish();
            if (!pubErr.ok()) {
                std::cerr << "Error publishing changes: " << pubErr.what() << std::endl;
                return;
            }
            
            std::cout << "Successfully published changes for " << gun << std::endl;
            
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
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