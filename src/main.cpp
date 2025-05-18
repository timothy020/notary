#include <iostream>
#include <CLI/CLI.hpp>
#include "notary/repository.hpp"
#include <filesystem>

using namespace notary;

// 加载配置
Error loadConfig(const std::string& configFile, std::string& trustDir, std::string& serverURL) {
    // 如果没有指定配置文件，使用默认值
    if (trustDir.empty()) {
        trustDir = std::filesystem::current_path().string() + "/trust";
    }
    
    if (serverURL.empty()) {
        serverURL = "https://localhost:4443";
    }
    
    // 确保信任目录存在
    try {
        if (!std::filesystem::exists(trustDir)) {
            std::filesystem::create_directories(trustDir);
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
    // TODO: 实现自动发布
    // 这里应该调用repo的发布方法
    
    return Error();
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
    
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    return 0;
} 