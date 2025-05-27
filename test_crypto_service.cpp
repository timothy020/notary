#include "notary/crypto/crypto_service.hpp"
#include "notary/storage/key_storage.hpp"
#include <iostream>
#include <memory>

using namespace notary;
using namespace notary::crypto;
using namespace notary::storage;

int main() {
    try {
        // 创建内存密钥存储
        auto keyStore = std::make_shared<GenericKeyStore>(
            std::make_shared<MemoryKeyStore>(),
            [](RoleName role) { return "test_password"; }
        );
        
        // 创建CryptoService
        auto cryptoService = CryptoService::NewCryptoService({keyStore});
        
        std::cout << "创建CryptoService成功" << std::endl;
        
        // 测试创建ECDSA密钥
        auto createResult = cryptoService->Create(RoleName::TARGETS, "test_gun", "ecdsa");
        if (createResult.ok()) {
            auto publicKey = createResult.value();
            std::cout << "成功创建ECDSA密钥，ID: " << publicKey->ID() << std::endl;
            
            // 测试获取密钥
            auto retrievedKey = cryptoService->GetKey(publicKey->ID());
            if (retrievedKey) {
                std::cout << "成功获取密钥，ID: " << retrievedKey->ID() << std::endl;
            } else {
                std::cout << "获取密钥失败" << std::endl;
            }
            
            // 测试列出密钥
            auto keys = cryptoService->ListKeys(RoleName::TARGETS);
            std::cout << "TARGETS角色的密钥数量: " << keys.size() << std::endl;
            
            // 测试列出所有密钥
            auto allKeys = cryptoService->ListAllKeys();
            std::cout << "所有密钥数量: " << allKeys.size() << std::endl;
            
        } else {
            std::cout << "创建密钥失败: " << createResult.error().message() << std::endl;
        }
        
        // 测试RSA密钥（应该失败）
        auto rsaResult = cryptoService->Create(RoleName::TARGETS, "test_gun", "rsa");
        if (!rsaResult.ok()) {
            std::cout << "RSA密钥创建正确失败: " << rsaResult.error().message() << std::endl;
        }
        
        std::cout << "所有测试完成" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "测试异常: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 