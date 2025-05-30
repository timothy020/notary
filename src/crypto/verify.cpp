#include "notary/crypto/verify.hpp"
#include "notary/crypto/verifiers.hpp"
#include "notary/utils/tools.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <set>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using json = nlohmann::json;

namespace notary {
namespace crypto {

// 基础签名错误常量
const std::string ErrNoSignatures = "tuf: data has no signatures";
const std::string ErrInvalid = "tuf: signature verification failed";
const std::string ErrWrongType = "tuf: meta file has wrong type";

// IsExpired 检查给定时间是否在当前时间之前
bool IsExpired(const std::chrono::time_point<std::chrono::system_clock>& t) {
    return t < std::chrono::system_clock::now();
}

// VerifyExpiry 如果元数据过期则返回错误
Error VerifyExpiry(const notary::tuf::SignedCommon& s, RoleName role) {
    if (IsExpired(s.Expires)) {
        // 格式化过期时间
        auto time_t = std::chrono::system_clock::to_time_t(s.Expires);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%a %b %d %H:%M:%S %Z %Y");
        
        // 这里应该使用ErrExpired异常，但由于我们使用Error类型，暂时返回Error
        return Error("Metadata for " + roleToString(role) + " expired on " + oss.str());
    }
    return Error();
}

// VerifyVersion 如果元数据版本低于最小版本则返回错误
Error VerifyVersion(const notary::tuf::SignedCommon& s, int minVersion) {
    if (s.Version < minVersion) {
        return Error("TUF metadata version " + std::to_string(s.Version) + 
                    " is lower than expected version " + std::to_string(minVersion));
    }
    return Error();
}

// VerifySignatures 检查给定角色是否有足够的有效签名
Error VerifySignatures(notary::tuf::Signed& s, const BaseRole& roleData) {
    if (s.Signatures.empty()) {
        return Error(ErrNoSignatures);
    }

    if (roleData.Threshold() < 1) {
        return Error("role threshold must be at least 1");
    }

    // 获取角色的密钥ID列表用于调试
    std::set<std::string> keyIDs;
    for (const auto& key : roleData.Keys()) {
        keyIDs.insert(key->ID());
    }
    
    // 重新编组签名部分，以便我们可以验证签名，因为签名必须是规范编组的签名对象
    try {
        std::string jsonStr(s.signedData.begin(), s.signedData.end());
        json decoded = json::parse(jsonStr);
        std::string canonicalJson = utils::MarshalCanonical(decoded);
        std::vector<uint8_t> msg(canonicalJson.begin(), canonicalJson.end());

        std::set<std::string> valid;
        for (auto& sig : s.Signatures) {
            // 查找对应的密钥
            std::shared_ptr<PublicKey> key = nullptr;
            for (const auto& roleKey : roleData.Keys()) {
                if (roleKey->ID() == sig.KeyID) {
                    key = roleKey;
                    break;
                }
            }
            
            if (!key) {
                continue; // 继续下一个签名
            }
            
            // 检查签名密钥ID是否实际匹配密钥的内容ID
            if (key->ID() != sig.KeyID) {
                return Error("key ID does not match content ID of key");
            }
            
            Error err = VerifySignature(msg, sig, key);
            if (err.hasError()) {
                continue; // 继续下一个签名
            }
            
            valid.insert(sig.KeyID);
        }
        
        if (static_cast<int>(valid.size()) < roleData.Threshold()) {
            return Error("valid signatures did not meet threshold for " + roleToString(roleData.Name()));
        }

        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error("Failed to process signatures: " + std::string(e.what()));
    }
}

// VerifySignature 检查单个签名和公钥对负载的验证
Error VerifySignature(const std::vector<uint8_t>& msg, 
                     notary::tuf::Signature& sig, 
                     std::shared_ptr<PublicKey> pk) {
    // 方法查找是一致的，因为Unmarshal JSON为我们做了小写处理
    std::string method = sig.Method;
    
    auto it = Verifiers.find(method);
    if (it == Verifiers.end()) {
        return Error("signing method is not supported: " + sig.Method);
    }
    
    Error err = it->second->Verify(pk, sig.Sig, msg);
    if (err.hasError()) {
        return Error("signature was invalid");
    }
    
    sig.IsValid = true;
    return Error();
}

// VerifyPublicKeyMatchesPrivateKey 检查私钥和公钥是否形成有效的密钥对
Error VerifyPublicKeyMatchesPrivateKey(std::shared_ptr<PrivateKey> privKey, 
                                      std::shared_ptr<PublicKey> pubKey) {
    if (!privKey) {
        return Error("private key is nil");
    }
    
    if (!pubKey) {
        return Error("public key is nil");
    }
    
    // TODO: 实现canonical key ID计算
    // 这需要使用utils库中的CanonicalKeyID函数
    
    if (privKey->ID() != pubKey->ID()) {
        return Error("private key does not match public key");
    }
    
    return Error();
}

} // namespace crypto
} // namespace notary
