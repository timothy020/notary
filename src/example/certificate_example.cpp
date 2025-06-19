#include "notary/crypto/certificate.hpp"
#include <iostream>
#include <chrono>

namespace notary {
namespace crypto {
namespace examples {

void demonstrateCertificateGeneration() {
    std::cout << "=== 证书生成功能演示 ===" << std::endl;
    
    try {
        // 示例：创建证书模板
        std::cout << "创建证书模板..." << std::endl;
        
        auto now = std::chrono::system_clock::now();
        auto endTime = now + std::chrono::hours(24 * 365); // 1年有效期
        
        X509* certTemplate = utils::NewCertificateTemplate(
            "docker.com/library/hello-world", 
            now, 
            endTime
        );
        
        if (certTemplate) {
            std::cout << "✅ 证书模板创建成功" << std::endl;
            
            // 创建Certificate对象
            auto cert = std::make_shared<utils::Certificate>(certTemplate);
            
            // 获取证书信息
            std::cout << "证书通用名称: " << cert->GetCommonName() << std::endl;
            std::cout << "证书是否有效: " << (cert->IsValid() ? "是" : "否") << std::endl;
            
            // 转换为PEM格式
            auto pemData = cert->ToPEM();
            if (!pemData.empty()) {
                std::cout << "✅ PEM格式转换成功，大小: " << pemData.size() << " 字节" << std::endl;
            }
            
            // 验证证书（不检查过期，因为没有私钥签名）
            bool isValid = ValidateCertificate(*cert, false);
            std::cout << "证书验证结果: " << (isValid ? "通过" : "失败") << std::endl;
            
        } else {
            std::cout << "❌ 证书模板创建失败" << std::endl;
        }
        
        // 示例：从文件加载证书（需要实际的证书文件）
        std::cout << "\n测试证书文件加载..." << std::endl;
        try {
            // 这里只是演示API，实际使用时需要真实的证书文件
            // auto loadedCert = LoadCertificateFromFile("test.pem");
            std::cout << "⚠️  证书文件加载需要实际的PEM文件" << std::endl;
        } catch (const utils::CertificateError& e) {
            std::cout << "预期的错误: " << e.what() << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
    }
    
    std::cout << "\n=== 演示完成 ===" << std::endl;
}

// 演示证书验证功能
void demonstrateCertificateValidation() {
    std::cout << "\n=== 证书验证功能演示 ===" << std::endl;
    
    try {
        auto now = std::chrono::system_clock::now();
        auto validEndTime = now + std::chrono::hours(24 * 365);
        auto expiredEndTime = now - std::chrono::hours(24); // 已过期
        
        // 创建有效的证书模板
        X509* validCert = utils::NewCertificateTemplate("valid.example.com", now, validEndTime);
        if (validCert) {
            utils::Certificate cert(validCert);
            std::cout << "有效证书验证结果: " << 
                (ValidateCertificate(cert, false) ? "通过" : "失败") << std::endl;
        }
        
        // 创建过期的证书模板  
        X509* expiredCert = utils::NewCertificateTemplate("expired.example.com", now, expiredEndTime);
        if (expiredCert) {
            utils::Certificate cert(expiredCert);
            std::cout << "过期证书验证结果（检查过期）: " << 
                (ValidateCertificate(cert, true) ? "通过" : "失败") << std::endl;
            std::cout << "过期证书验证结果（不检查过期）: " << 
                (ValidateCertificate(cert, false) ? "通过" : "失败") << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "验证演示错误: " << e.what() << std::endl;
    }
}

}
}
}

// 如果直接运行此文件
#ifdef CERTIFICATE_EXAMPLE_MAIN
int main() {
    notary::crypto::examples::demonstrateCertificateGeneration();
    notary::crypto::examples::demonstrateCertificateValidation();
    return 0;
}
#endif 