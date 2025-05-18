#include <iostream>
#include <string>
#include <vector>
#include <CLI/CLI.hpp>
#include "notary/server/server.hpp"
#include "notary/crypto/crypto_service.hpp"

int main(int argc, char* argv[]) {
    CLI::App app{"Notary服务器 - TUF元数据管理"};
    
    std::string addr = "localhost:4443";
    std::string keyAlgorithm = "ecdsa";
    std::vector<std::string> repoPrefixes;
    std::string trustDir = ".";
    
    // 添加命令行参数
    app.add_option("--addr", addr, "服务器监听地址, 格式: host:port");
    app.add_option("--key-algorithm", keyAlgorithm, "密钥算法, 支持: ecdsa, rsa, ed25519");
    app.add_option("--repo-prefix", repoPrefixes, "仓库前缀, 可多次指定");
    app.add_option("--trust-dir", trustDir, "信任数据目录");
    
    // 解析命令行参数
    try {
        app.parse(argc, argv);
    } catch(const CLI::ParseError& e) {
        return app.exit(e);
    }
    
    // 打印配置
    std::cout << "Notary服务器配置:" << std::endl;
    std::cout << "  监听地址: " << addr << std::endl;
    std::cout << "  密钥算法: " << keyAlgorithm << std::endl;
    std::cout << "  信任目录: " << trustDir << std::endl;
    if (!repoPrefixes.empty()) {
        std::cout << "  仓库前缀:" << std::endl;
        for (const auto& prefix : repoPrefixes) {
            std::cout << "    - " << prefix << std::endl;
        }
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
    
    // 创建并运行服务器
    notary::server::Server server(config);
    auto err = server.Run();
    if (err.Code() != 0) { // 0 = NoError
        std::cerr << "服务器启动失败: " << err.Detail() << std::endl;
        return 1;
    }
    
    return 0;
} 