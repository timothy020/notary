#include "notary/utils/x509.hpp"
#include "notary/crypto/keys.hpp"
#include "notary/utils/logger.hpp"
#include <iostream>
#include <fstream>
#include <chrono>

namespace notary {
namespace utils {

// 演示CertToKey函数的使用
void demonstrateCertToKey() {
    std::cout << "\n=== CertToKey函数演示 ===" << std::endl;
    
    try {
        // 1. 创建证书模板
        std::cout << "1. 创建证书模板..." << std::endl;
        auto now = std::chrono::system_clock::now();
        auto oneYear = now + std::chrono::hours(24 * 365);
        
        X509* certTemplate = NewCertificateTemplate(
            "test.example.com",
            now,
            oneYear
        );
        
        if (!certTemplate) {
            std::cout << "❌ 创建证书模板失败" << std::endl;
            return;
        }
        
        std::cout << "✅ 证书模板创建成功" << std::endl;
        
        // 注意：在实际使用中，您需要为证书设置公钥并签名
        // 这里我们只演示如何从已有证书提取公钥
        
        // 2. 测试CertToKey函数
        std::cout << "\n2. 从证书提取公钥..." << std::endl;
        
        // 为了演示，我们需要先为证书设置一个公钥
        // 在实际应用中，证书应该已经包含有效的公钥
        
        // 由于这是一个演示函数，我们创建一个简单的测试用例
        auto publicKey = CertToKey(certTemplate);
        
        if (publicKey) {
            std::cout << "✅ 成功从证书提取公钥" << std::endl;
            std::cout << "   密钥算法: " << publicKey->Algorithm() << std::endl;
            std::cout << "   密钥ID: " << publicKey->ID() << std::endl;
        } else {
            std::cout << "❌ 从证书提取公钥失败（这是预期的，因为证书模板没有公钥）" << std::endl;
        }
        
        // 3. 使用Certificate包装类
        std::cout << "\n3. 使用Certificate包装类..." << std::endl;
        Certificate cert(certTemplate);
        
        if (cert.IsValid()) {
            std::cout << "✅ Certificate对象创建成功" << std::endl;
            std::cout << "   通用名称: " << cert.GetCommonName() << std::endl;
            
            // 使用Certificate版本的CertToKey
            auto publicKey2 = CertToKey(cert);
            if (publicKey2) {
                std::cout << "✅ 通过Certificate对象成功提取公钥" << std::endl;
            } else {
                std::cout << "❌ 通过Certificate对象提取公钥失败（预期结果）" << std::endl;
            }
        }
        
        // 4. 演示不同密钥类型的处理
        std::cout << "\n4. 密钥类型支持说明:" << std::endl;
        std::cout << "   ✅ RSA密钥 -> RSAx509PublicKey" << std::endl;
        std::cout << "   ✅ ECDSA密钥 -> ECDSAx509PublicKey" << std::endl;
        std::cout << "   ❌ 其他类型 -> 返回nullptr并记录错误" << std::endl;
        
        // 清理资源
        X509_free(certTemplate);
        
    } catch (const std::exception& e) {
        std::cout << "❌ 异常: " << e.what() << std::endl;
    }
}

// 从PEM文件演示CertToKey
void demonstrateCertToKeyFromFile(const std::string& pemFile) {
    std::cout << "\n=== 从PEM文件提取公钥演示 ===" << std::endl;
    
    try {
        // 检查文件是否存在
        std::ifstream file(pemFile);
        if (!file.good()) {
            std::cout << "⚠️  文件不存在: " << pemFile << std::endl;
            std::cout << "   创建一个示例PEM证书文件来测试此功能" << std::endl;
            return;
        }
        
        // 从文件加载证书
        auto cert = LoadCertificateFromFile(pemFile);
        if (!cert) {
            std::cout << "❌ 从文件加载证书失败: " << pemFile << std::endl;
            return;
        }
        
        std::cout << "✅ 成功从文件加载证书: " << pemFile << std::endl;
        std::cout << "   通用名称: " << cert->GetCommonName() << std::endl;
        
        // 使用CertToKey提取公钥
        auto publicKey = CertToKey(*cert);
        if (publicKey) {
            std::cout << "✅ 成功从证书提取公钥" << std::endl;
            std::cout << "   密钥算法: " << publicKey->Algorithm() << std::endl;
            std::cout << "   密钥ID: " << publicKey->ID() << std::endl;
            
            // 获取公钥字节数据
            auto pubBytes = publicKey->Public();
            std::cout << "   公钥数据长度: " << pubBytes.size() << " 字节" << std::endl;
            
        } else {
            std::cout << "❌ 从证书提取公钥失败" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cout << "❌ 异常: " << e.what() << std::endl;
    }
}

// API文档说明
void showCertToKeyAPI() {
    std::cout << "\n=== CertToKey API 文档 ===" << std::endl;
    std::cout << R"(
功能描述:
  CertToKey函数将X509证书转换为对应的TUF PublicKey对象

函数签名:
  std::shared_ptr<crypto::PublicKey> CertToKey(X509* cert);
  std::shared_ptr<crypto::PublicKey> CertToKey(const Certificate& cert);

参数说明:
  cert - X509证书指针或Certificate对象

返回值:
  - 成功: 返回对应的PublicKey智能指针
    * RSA证书 -> RSAx509PublicKey
    * ECDSA证书 -> ECDSAx509PublicKey
  - 失败: 返回nullptr

实现对应关系 (Go -> C++):
  data.NewRSAx509PublicKey(pemdata)   -> crypto::NewRSAx509PublicKey(pemBytes)
  data.NewECDSAx509PublicKey(pemdata) -> crypto::NewECDSAx509PublicKey(pemBytes)

错误处理:
  - 证书为空
  - DER编码失败
  - PEM转换失败
  - 公钥提取失败
  - 不支持的密钥类型

使用示例:
  auto cert = LoadCertificateFromFile("cert.pem");
  auto publicKey = CertToKey(*cert);
  if (publicKey) {
      std::cout << "密钥算法: " << publicKey->Algorithm() << std::endl;
      std::cout << "密钥ID: " << publicKey->ID() << std::endl;
  }
)";
}

} // namespace utils
} // namespace notary

// 主函数 - 演示用法
int main() {
    std::cout << "=== C++ Notary CertToKey 功能演示 ===" << std::endl;
    
    // 基本演示
    notary::utils::demonstrateCertToKey();
    
    // 从文件演示（如果有证书文件的话）
    notary::utils::demonstrateCertToKeyFromFile("test_cert.pem");
    
    // 显示API文档
    notary::utils::showCertToKeyAPI();
    
    std::cout << "\n=== 演示完成 ===" << std::endl;
    return 0;
} 