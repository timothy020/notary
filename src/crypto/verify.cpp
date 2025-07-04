#include "notary/crypto/verify.hpp"
#include "notary/crypto/verifiers.hpp"
#include "notary/utils/tools.hpp"
#include "notary/utils/x509.hpp"
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
Error VerifyExpiry(const notary::tuf::SignedCommon& s, const std::string& role) {
    if (IsExpired(s.Expires)) {
        // 格式化过期时间
        auto time_t = std::chrono::system_clock::to_time_t(s.Expires);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%a %b %d %H:%M:%S %Z %Y");
        
        // 这里应该使用ErrExpired异常，但由于我们使用Error类型，暂时返回Error
        return Error("Metadata for " + role + " expired on " + oss.str());
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
            return Error("valid signatures did not meet threshold for " + roleData.Name());
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

// VerifyPublicKeyMatchesPrivateKey checks if the private key and the public keys forms valid key pairs.
// Supports both x509 certificate PublicKeys and non-certificate PublicKeys
// 对应Go版本的signed.VerifyPublicKeyMatchesPrivateKey函数
Error VerifyPublicKeyMatchesPrivateKey(std::shared_ptr<PrivateKey> privKey, 
                                      std::shared_ptr<PublicKey> pubKey) {
    // 检查私钥是否为空（对应Go版本的 privKey == nil）
    if (!privKey) {
        return Error("private key is nil or does not match public key");
    }
    
    // 检查公钥是否为空
    if (!pubKey) {
        return Error("public key is nil");
    }
    
    // 获取公钥的规范化ID（对应Go版本的 utils.CanonicalKeyID(pubKey)）
    std::string pubKeyID = utils::CanonicalKeyID(pubKey);
    if (pubKeyID.empty()) {
        return Error("could not verify key pair: failed to get canonical key ID");
    }
    
    // 获取私钥的ID
    std::string privKeyID = privKey->ID();
    if (privKeyID.empty()) {
        return Error("could not verify key pair: private key ID is empty");
    }
    
    // 比较规范化的公钥ID与私钥ID（对应Go版本的 pubKeyID != privKey.ID()）
    if (pubKeyID != privKeyID) {
        utils::GetLogger().Debug("Key ID mismatch - Public key canonical ID: " + pubKeyID + 
                                ", Private key ID: " + privKeyID);
        return Error("private key is nil or does not match public key");
    }
    
    utils::GetLogger().Debug("Successfully verified public key matches private key, ID: " + pubKeyID);
    
    // 成功时返回空错误（对应Go版本的 return nil）
    return Error();
}

} // namespace crypto
} // namespace notary
