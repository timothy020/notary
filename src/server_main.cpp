#include <iostream>
#include <string>
#include <vector>
#include <CLI/CLI.hpp>
#include "notary/server/server.hpp"
#include "notary/crypto/crypto_service.hpp"
#include "notary/utils/logger.hpp"

int main(int argc, char* argv[]) {
    CLI::App app{"Notary服务器 - TUF元数据管理"};
    
    std::string addr = "localhost:4443";
    std::string keyAlgorithm = "ecdsa";
    std::vector<std::string> repoPrefixes;
    std::string trustDir = ".";
    
    // 日志配置
    std::string logLevel = "info";
    std::string logFormat = "json";
    std::string logOutput = "console";
    std::string logFile = "notary-server.log";
    
    // 添加命令行参数
    app.add_option("--addr", addr, "服务器监听地址, 格式: host:port");
    app.add_option("--key-algorithm", keyAlgorithm, "密钥算法, 支持: ecdsa, rsa, ed25519");
    app.add_option("--repo-prefix", repoPrefixes, "仓库前缀, 可多次指定");
    app.add_option("--trust-dir", trustDir, "信任数据目录");
    
    // 添加日志配置选项
    app.add_option("--log-level", logLevel, "日志级别: debug, info, warn, error, fatal, panic");
    app.add_option("--log-format", logFormat, "日志格式: json, text");
    app.add_option("--log-output", logOutput, "日志输出: console, file");
    app.add_option("--log-file", logFile, "日志文件路径(当log-output为file时使用)");
    
    // 解析命令行参数
    try {
        app.parse(argc, argv);
    } catch(const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    // 初始化默认日志系统
    notary::utils::GetLogger().Initialize(logLevel, logFormat, logOutput);
    
    // 打印配置
    notary::utils::GetLogger().Info("Notary服务器配置", 
        notary::utils::LogContext()
            .With("addr", addr)
            .With("keyAlgorithm", keyAlgorithm)
            .With("trustDir", trustDir)
            .With("logLevel", logLevel)
            .With("logFormat", logFormat)
            .With("logOutput", logOutput));
    
    if (!repoPrefixes.empty()) {
        std::string prefixesStr;
        for (size_t i = 0; i < repoPrefixes.size(); ++i) {
            if (i > 0) prefixesStr += ", ";
            prefixesStr += repoPrefixes[i];
        }
        notary::utils::GetLogger().Info("仓库前缀", 
            notary::utils::LogContext().With("prefixes", prefixesStr));
    }
    
    // 创建加密服务
    notary::crypto::CryptoService cryptoService;
    cryptoService.SetDefaultPassphrase("server");
    
    // 创建服务器配置
    notary::server::Config config;
    config.addr = addr;
    config.cryptoService = &cryptoService;
    config.keyAlgorithm = keyAlgorithm;
    config.repoPrefixes = repoPrefixes;
    
    // 设置日志配置
    config.logging.level = logLevel;
    config.logging.format = logFormat;
    config.logging.output = logOutput;
    config.logging.file = logFile;
    
    // 创建并运行服务器
    notary::server::Server server(config);
    auto err = server.Run();
    if (err.Code() != 0) { // 0 = NoError
        notary::utils::GetLogger().Fatal("服务器启动失败", 
            notary::utils::LogContext().With("error", err.Detail()));
        return 1;
    }
    
    return 0;
} 