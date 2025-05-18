#pragma once

#include <vector>
#include <memory>
#include <string>
#include <map>

namespace notary {
namespace crypto {

class PublicKey {
public:
    virtual ~PublicKey() = default;
    virtual std::string ID() const = 0;
};

class PrivateKey {
public:
    virtual ~PrivateKey() = default;
    virtual std::shared_ptr<PublicKey> Public() const = 0;
};

class ECDSAPublicKey : public PublicKey {
public:
    explicit ECDSAPublicKey(const std::vector<uint8_t>& derData) : derData_(derData) {}
    std::string ID() const override;
    
    // 获取DER编码数据
    const std::vector<uint8_t>& GetDERData() const { return derData_; }
    
private:
    std::vector<uint8_t> derData_;
};

class ECDSAPrivateKey : public PrivateKey {
public:
    ECDSAPrivateKey(std::shared_ptr<PublicKey> pub, const std::vector<uint8_t>& derData)
        : public_(pub), derData_(derData) {}
    std::shared_ptr<PublicKey> Public() const override { return public_; }
    
    // 获取私钥DER编码数据
    const std::vector<uint8_t>& GetDERData() const { return derData_; }
    
private:
    std::shared_ptr<PublicKey> public_;
    std::vector<uint8_t> derData_;
};

} // namespace crypto
} // namespace notary