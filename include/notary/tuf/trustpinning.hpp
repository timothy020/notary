#pragma once

#include <map>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include "notary/utils/x509.hpp"

namespace notary {
namespace tuf {
// Trust Pin配置类 - 对应Go版本的TrustPinConfig
class TrustPinConfig {
public:
    TrustPinConfig() = default;
    
    // CA映射：GUN前缀到CA文件路径 (暂未实现)
    std::map<std::string, std::string> ca;
    // 证书映射：GUN到证书ID列表 (暂未实现)  
    std::map<std::string, std::vector<std::string>> certs;
    
    // 是否禁用TOFU (Trust On First Use)
    bool disableTOFU = false;
};

// 证书检查器函数类型 - 对应Go版本的CertChecker
// 参数：叶子证书，中间证书列表
// 返回：是否通过验证
using CertChecker = std::function<bool(
    const std::shared_ptr<utils::Certificate>& leafCert,
    const std::vector<std::shared_ptr<utils::Certificate>>& intCerts
)>;

// Trust Pin检查器类 - 对应Go版本的trustPinChecker
class TrustPinChecker {
private:
    std::string gun_;
    TrustPinConfig config_;
    
public:
    TrustPinChecker(const std::string& gun, const TrustPinConfig& config);
    
    // TOFU检查 - 对应Go版本的tofusCheck
    bool tofusCheck(
        const std::shared_ptr<utils::Certificate>& leafCert,
        const std::vector<std::shared_ptr<utils::Certificate>>& intCerts
    ) const;
    
    // 证书检查 (暂未实现)
    bool certsCheck(
        const std::shared_ptr<utils::Certificate>& leafCert,
        const std::vector<std::shared_ptr<utils::Certificate>>& intCerts
    ) const;
    
    // CA检查 (暂未实现)  
    bool caCheck(
        const std::shared_ptr<utils::Certificate>& leafCert,
        const std::vector<std::shared_ptr<utils::Certificate>>& intCerts
    ) const;
};

// 创建Trust Pin检查器 - 对应Go版本的NewTrustPinChecker
// 参数：trust pin配置，GUN，是否首次引导
// 返回：证书检查器函数
CertChecker NewTrustPinChecker(
    const TrustPinConfig& trustPinConfig, 
    const std::string& gun, 
    bool firstBootstrap = false
);

// 通配符匹配 (暂未实现)
std::pair<std::vector<std::string>, bool> wildcardMatch(
    const std::string& gun, 
    const std::map<std::string, std::vector<std::string>>& certs
);

// 根据前缀获取CA文件路径 (暂未实现)
std::pair<std::string, bool> getPinnedCAFilepathByPrefix(
    const std::string& gun, 
    const TrustPinConfig& config
);

}
}