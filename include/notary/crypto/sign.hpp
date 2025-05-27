#pragma once

#include "notary/types.hpp"
#include "notary/crypto/crypto_service.hpp"
#include "notary/tuf/repo.hpp"

namespace notary {
namespace crypto {

// 签名不足错误类型
class ErrInsufficientSignatures : public Error {
public:
    ErrInsufficientSignatures(int foundKeys, int neededKeys, const std::vector<std::string>& missingKeyIDs)
        : Error("Insufficient signatures"), foundKeys_(foundKeys), neededKeys_(neededKeys), missingKeyIDs_(missingKeyIDs) {}
    
    int FoundKeys() const { return foundKeys_; }
    int NeededKeys() const { return neededKeys_; }
    const std::vector<std::string>& MissingKeyIDs() const { return missingKeyIDs_; }
    
private:
    int foundKeys_;
    int neededKeys_;
    std::vector<std::string> missingKeyIDs_;
};

// 主要的Sign函数
Error Sign(CryptoService& service, std::shared_ptr<tuf::Signed> s, 
          const std::vector<std::shared_ptr<PublicKey>>& signingKeys,
          int minSignatures, 
          const std::vector<std::shared_ptr<PublicKey>>& otherWhitelistedKeys = {});

}
}