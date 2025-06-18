#include "notary/tuf/trustpinning.hpp"
#include <iostream>
#include <memory>

namespace notary {
namespace tuf {
namespace examples {

void demonstrateTrustPinning() {
    std::cout << "=== Trust Pinning 使用示例 ===" << std::endl;
    
    try {
        // 1. 创建Trust Pin配置
        TrustPinConfig config;
        config.disableTOFU = false;  // 启用TOFU
        
        // 2. 创建GUN (Globally Unique Name)
        std::string gun("docker.com/library/hello-world");
        
        // 3. 创建Trust Pin检查器 (TOFU模式)
        std::cout << "创建TOFU模式的Trust Pin检查器..." << std::endl;
        auto certChecker = NewTrustPinChecker(config, gun, true);
        
        // 4. 模拟证书验证
        std::shared_ptr<data::Certificate> leafCert = nullptr;  // 实际使用时需要真实证书
        std::vector<std::shared_ptr<data::Certificate>> intCerts;
        
        std::cout << "执行TOFU证书检查..." << std::endl;
        bool isValid = certChecker(leafCert, intCerts);
        std::cout << "TOFU检查结果: " << (isValid ? "通过" : "失败") << std::endl;
        
        // 5. 测试禁用TOFU的情况
        std::cout << "\n测试禁用TOFU的情况..." << std::endl;
        TrustPinConfig disabledConfig;
        disabledConfig.disableTOFU = true;
        
        try {
            auto disabledChecker = NewTrustPinChecker(disabledConfig, gun, true);
            std::cout << "意外通过：禁用TOFU时应该抛出异常" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "正确行为：" << e.what() << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
    }
    
    std::cout << "\n=== 示例完成 ===" << std::endl;
}

}
}
}

// 如果直接运行此文件
#ifdef TRUSTPINNING_EXAMPLE_MAIN
int main() {
    notary::tuf::examples::demonstrateTrustPinning();
    return 0;
}
#endif 