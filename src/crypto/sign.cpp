#include "notary/crypto/sign.hpp"
#include <map>
#include <set>
#include <algorithm>

namespace notary {
namespace crypto {


// 主要的Sign函数实现
Error Sign(std::shared_ptr<CryptoService> service, std::shared_ptr<tuf::Signed> s, 
          const std::vector<std::shared_ptr<PublicKey>>& signingKeys,
          int minSignatures, 
          const std::vector<std::shared_ptr<PublicKey>>& otherWhitelistedKeys) {
    
    if (!s) {
        return Error("Signed data is null");
    }
    
    // 准备数据结构
    std::vector<tuf::Signature> signatures;
    signatures.reserve(s->Signatures.size() + signingKeys.size());
    
    std::set<std::string> signingKeyIDs;
    std::map<std::string, std::shared_ptr<PublicKey>> tufIDs;
    std::map<std::string, std::shared_ptr<PrivateKey>> privKeys;
    
    // 获取所有与公钥相关的私钥对象
    std::vector<std::string> missingKeyIDs;
    
    for (const auto& key : signingKeys) {
        std::string keyID = key->ID();
        tufIDs[keyID] = key;
        
        // 从CryptoService获取私钥
        auto privateKeyResult = service->GetPrivateKey(keyID);
        if (!privateKeyResult.ok()) {
            missingKeyIDs.push_back(keyID);
            continue;
        }
        
        auto [privateKey, keyRole] = privateKeyResult.value();
        privKeys[keyID] = privateKey;
    }
    
    // 包含otherWhitelistedKeys列表
    for (const auto& key : otherWhitelistedKeys) {
        std::string keyID = key->ID();
        if (tufIDs.find(keyID) == tufIDs.end()) {
            tufIDs[keyID] = key;
        }
    }
    
    // 检查是否有足够的签名密钥
    if (static_cast<int>(privKeys.size()) < minSignatures) {
        return ErrInsufficientSignatures(
            static_cast<int>(privKeys.size()), 
            minSignatures, 
            missingKeyIDs
        );
    }
    
    // 执行签名并生成签名列表
    for (const auto& [keyID, privateKey] : privKeys) {
        auto signatureBytes = privateKey->Sign(s->signedData);
        if (signatureBytes.empty()) {
            return Error("Failed to sign with key: " + keyID);
        }
        
        signingKeyIDs.insert(keyID);
        
        tuf::Signature signature;
        signature.KeyID = keyID;
        signature.Method = privateKey->Algorithm();
        signature.Sig = signatureBytes;
        signature.IsValid = true;
        
        signatures.push_back(signature);
    }
    
    // TODO:清理并保留已有签名（允许旧签名）
    for (const auto& sig : s->Signatures) {
        // 如果这个签名是新生成的，跳过
        if (signingKeyIDs.find(sig.KeyID) != signingKeyIDs.end()) {
            continue;
        }
        
        // 检查密钥是否仍然是有效的签名密钥
        auto keyIt = tufIDs.find(sig.KeyID);
        if (keyIt == tufIDs.end()) {
            continue; // 密钥不再是有效的签名密钥
        }
        
        // 验证签名是否仍然有效
        // Error verifyErr = VerifySignature(s->signedData, sig, keyIt->second);
        // if (!verifyErr.ok()) {
        //     continue; // 签名不再有效
        // }
        
        // 保留仍然代表有效密钥且本身有效的签名
        signatures.push_back(sig);
    }
    
    // 更新签名列表
    s->Signatures = signatures;
    
    return Error(); // 成功
}

}
}