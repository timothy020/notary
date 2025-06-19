#pragma once

#include <vector>
#include <memory>
#include <string>
#include <map>
#include <functional>
#include "notary/utils/logger.hpp"
#include "notary/types.hpp"

namespace notary {
namespace crypto {


// 密钥对结构
struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

// 公钥接口
class PublicKey {
public:
    virtual ~PublicKey() = default;
    
    // 获取密钥ID（SHA256哈希的十六进制表示）
    virtual std::string ID() = 0;
    
    // 获取密钥算法类型
    virtual std::string Algorithm() const = 0;
    
    // 获取公钥字节数据
    virtual std::vector<uint8_t> Public() const = 0;
};

// 私钥接口，继承公钥接口
class PrivateKey : public PublicKey {
public:
    virtual ~PrivateKey() = default;
    
    // 数字签名方法
    virtual std::vector<uint8_t> Sign(const std::vector<uint8_t>& message) const = 0;
    
    // 获取私钥字节数据
    virtual std::vector<uint8_t> Private() const = 0;
    
    // 获取签名算法
    virtual std::string GetSignatureAlgorithm() const = 0;
    
    // 获取对应的公钥
    virtual std::shared_ptr<PublicKey> GetPublicKey() const = 0;
};

// TUFKey 是 TUF 中用于公钥和私钥的结构。
// 通常来说,使用不同的结构来表示公钥和私钥是更合理的,
// 但这样会改变密钥 ID 的计算算法(因为规范化的 JSON 会不同)。
// 这个结构通常应该通过 PublicKey 或 PrivateKey 接口来访问。
class TUFKey : public PublicKey {
public:
    TUFKey() = default;
    TUFKey(const std::string& keyType, const std::vector<uint8_t>& publicKey, const std::vector<uint8_t>& privateKey = {})
        : type(keyType), value{publicKey, privateKey} {}
    
    std::string Algorithm() const override;
    std::string ID() override;
    std::vector<uint8_t> Public() const override;
private:
    std::string id;
    std::string type;
    KeyPair value;
};


// ECDSAPublicKey is a public key for ECDSA
class ECDSAPublicKey : public TUFKey {
public:
    ECDSAPublicKey(const std::vector<uint8_t>& publicKey)
        : TUFKey(ECDSA_KEY, publicKey, std::vector<uint8_t>()) {}
    ECDSAPublicKey(const std::string& keyType, const std::vector<uint8_t>& publicKey, const std::vector<uint8_t>& privateKey = {})
        : TUFKey(keyType, publicKey, privateKey) {}
};

// ECDSAx509PublicKey represents an ECDSA key using an x509 cert
// as the serialized format of the public key
class ECDSAx509PublicKey : public TUFKey {
public:
    ECDSAx509PublicKey(const std::vector<uint8_t>& x509Data)
        : TUFKey(ECDSA_X509_KEY, x509Data, std::vector<uint8_t>()) {}
};

// RSAPublicKey represents an RSA key using a raw serialization
// of the public key
class RSAPublicKey : public TUFKey {
public:
    RSAPublicKey(const std::vector<uint8_t>& publicKey)
        : TUFKey(RSA_KEY, publicKey, std::vector<uint8_t>()) {}
};

// RSAx509PublicKey represents an RSA key using an x509 cert
// as the serialized format of the public key
class RSAx509PublicKey : public TUFKey {
public:
    RSAx509PublicKey(const std::vector<uint8_t>& x509Data)
        : TUFKey(RSA_X509_KEY, x509Data, std::vector<uint8_t>()) {}
};

// ECDAPrivateKey is a private key for ECDSA
class ECDSAPrivateKey : public PrivateKey {  // PrivateKey继承自PublicKey
public:
    // 接受shared_ptr参数的构造函数
    ECDSAPrivateKey(std::shared_ptr<ECDSAPublicKey> publicKey, const std::vector<uint8_t>& privateKey)
        : publicKey_(publicKey), privateData_(privateKey) {}
    
    // 接受引用参数的构造函数（保持向后兼容）
    // ECDSAPrivateKey(const ECDSAPublicKey& publicKey, const std::vector<uint8_t>& privateKey)
    //     : publicKey_(std::make_shared<ECDSAPublicKey>(publicKey)), privateData_(privateKey) {}
    
    // 继承自PublicKey的方法
    std::string ID() override { return publicKey_->ID(); }
    std::string Algorithm() const override { return publicKey_->Algorithm(); }
    std::vector<uint8_t> Public() const override { return publicKey_->Public(); }
    
    // PrivateKey特有方法
    std::vector<uint8_t> Sign(const std::vector<uint8_t>& message) const override;
    std::vector<uint8_t> Private() const override { return privateData_; }
    std::string GetSignatureAlgorithm() const override;
    std::shared_ptr<PublicKey> GetPublicKey() const override { return publicKey_; }

private:
    std::shared_ptr<PublicKey> publicKey_;  // 组合方式实现
    std::vector<uint8_t> privateData_;
};

// 工厂函数
std::shared_ptr<PublicKey> NewPublicKey(const std::string& algorithm, const std::vector<uint8_t>& publicData);
std::shared_ptr<PrivateKey> NewPrivateKey(std::shared_ptr<PublicKey> publicKey, const std::vector<uint8_t>& privateData);

// 工厂函数：创建特定类型的公钥（对应Go版本的NewECDSAPublicKey和NewRSAPublicKey）
std::shared_ptr<ECDSAPublicKey> NewECDSAPublicKey(const std::vector<uint8_t>& publicData);
std::shared_ptr<RSAPublicKey> NewRSAPublicKey(const std::vector<uint8_t>& publicData);

// 工厂函数：创建x509公钥
std::shared_ptr<PublicKey> NewRSAx509PublicKey(const std::vector<uint8_t>& x509Data);
std::shared_ptr<PublicKey> NewECDSAx509PublicKey(const std::vector<uint8_t>& x509Data);

} // namespace crypto
} // namespace notary