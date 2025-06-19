#pragma once

#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <openssl/x509.h>
#include "notary/crypto/keys.hpp"
#include "notary/utils/x509.hpp"

namespace notary {
namespace crypto {

// 生成X509证书 - 对应Go版本的GenerateCertificate函数
// 参数说明:
// - rootKey: 用于签名证书的根私钥
// - gun: 全局唯一名称(Globally Unique Name)，用于标识证书所有者
// - startTime: 证书有效期的开始时间
// - endTime: 证书有效期的结束时间
// 返回值:
// - std::shared_ptr<Certificate>: 生成的证书对象
std::shared_ptr<utils::Certificate> GenerateCertificate(
    std::shared_ptr<PrivateKey> rootKey,
    const std::string& gun,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
);


// 验证证书有效性 - 对应Go版本utils.ValidateCertificate函数
// 参数说明:
// - cert: 要验证的证书
// - checkExpiry: 是否检查证书过期时间
// 返回值:
// - bool: 证书是否有效
bool ValidateCertificate(const utils::Certificate& cert, bool checkExpiry = true);

// 内部辅助函数声明
std::shared_ptr<utils::Certificate> generateCertificateInternal(
    std::shared_ptr<PrivateKey> privateKey,
    const std::string& gun,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
);


}
}