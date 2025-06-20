#pragma once

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <exception>
#include "notary/utils/x509.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/tuf/trustpinning.hpp"

namespace notary {
namespace tuf {

// 验证失败错误类 - 对应Go版本的ErrValidationFail
class ErrValidationFail : public std::exception {
public:
    explicit ErrValidationFail(const std::string& reason) : reason_(reason) {
        message_ = "could not validate the path to a trusted root: " + reason;
    }
    
    const char* what() const noexcept override { return message_.c_str(); }
    const std::string& getReason() const { return reason_; }
    
private:
    std::string reason_;
    std::string message_;
};

// 根密钥轮转失败错误类 - 对应Go版本的ErrRootRotationFail
class ErrRootRotationFail : public std::exception {
public:
    explicit ErrRootRotationFail(const std::string& reason) : reason_(reason) {
        message_ = "could not rotate trust to a new trusted root: " + reason;
    }
    
    const char* what() const noexcept override { return message_.c_str(); }
    const std::string& getReason() const { return reason_; }
    
private:
    std::string reason_;
    std::string message_;
};

// 格式化证书ID列表的辅助函数 - 对应Go版本的prettyFormatCertIDs
std::string prettyFormatCertIDs(const std::map<std::string, std::shared_ptr<utils::Certificate>>& certs);

// parseAllCerts returns two maps, one with all of the leafCertificates and one
// with all the intermediate certificates found in signedRoot
// 对应Go版本的trustpinning.parseAllCerts函数
// 参数说明:
// - signedRoot: 签名的Root元数据对象
// 返回值:
// - std::pair<std::map<std::string, std::shared_ptr<utils::Certificate>>, 
//             std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>>
//   第一个map是叶子证书(keyID -> Certificate)，第二个map是中间证书(keyID -> Certificate列表)
// - 如果signedRoot为空或无效，返回空的maps
std::pair<std::map<std::string, std::shared_ptr<utils::Certificate>>, 
          std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>>
parseAllCerts(std::shared_ptr<SignedRoot> signedRoot);

// MatchCNToGun checks that the common name in a cert is valid for the given gun.
// This allows wildcards as suffixes, e.g. `namespace/*`
// 对应Go版本的trustpinning.MatchCNToGun函数
// 参数说明:
// - commonName: 证书中的通用名称
// - gun: 要检查的GUN (Globally Unique Name)
// 返回值:
// - bool: 如果CN与GUN匹配则返回true，否则返回false
bool MatchCNToGun(const std::string& commonName, const std::string& gun);

// validRootLeafCerts returns a list of possibly (if checkExpiry is true) non-expired, non-sha1 certificates
// found in root whose Common-Names match the provided GUN. Note that this
// "validity" alone does not imply any measure of trust.
// 对应Go版本的trustpinning.validRootLeafCerts函数
// 参数说明:
// - allLeafCerts: 所有叶子证书的映射 (keyID -> Certificate)
// - gun: 要匹配的GUN
// - checkExpiry: 是否检查证书过期时间
// 返回值:
// - std::pair<std::map<std::string, std::shared_ptr<utils::Certificate>>, Error>:
//   第一个是有效的叶子证书映射，第二个是错误信息
std::pair<std::map<std::string, std::shared_ptr<utils::Certificate>>, Error>
validRootLeafCerts(const std::map<std::string, std::shared_ptr<utils::Certificate>>& allLeafCerts, 
                   const std::string& gun, 
                   bool checkExpiry);

// validRootIntCerts filters the passed in structure of intermediate certificates to only include non-expired, non-sha1 certificates
// Note that this "validity" alone does not imply any measure of trust.
// 对应Go版本的trustpinning.validRootIntCerts函数
// 参数说明:
// - allIntCerts: 所有中间证书的映射 (keyID -> Certificate列表)
// 返回值:
// - std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>: 有效的中间证书映射
std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>
validRootIntCerts(const std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>& allIntCerts);

// ValidateRoot receives a new root, validates its correctness and attempts to
// do root key rotation if needed - 对应Go版本的trustpinning.ValidateRoot函数
Result<std::shared_ptr<SignedRoot>> ValidateRoot(
    std::shared_ptr<SignedRoot> prevRoot,
    std::shared_ptr<tuf::Signed> root,
    const std::string& gun,
    const TrustPinConfig& trustPinning
);

}
}
