#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <utility>
#include "notary/types.hpp"
#include "notary/crypto/keys.hpp"

namespace notary {
namespace crypto {
// 验证器接口
class Verifier {
public:
    virtual ~Verifier() = default;
    virtual Error Verify(std::shared_ptr<PublicKey> key, 
                        const std::vector<uint8_t>& signature, 
                        const std::vector<uint8_t>& message) = 0;
};

// 全局验证器注册表
extern const std::unordered_map<std::string, std::shared_ptr<Verifier>> Verifiers;

// RSA PSS验证器
class RSAPSSVerifier : public Verifier {
public:
    Error Verify(std::shared_ptr<PublicKey> key, 
                const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& message) override;
};

// RSA PKCS1v15验证器
class RSAPKCS1v15Verifier : public Verifier {
public:
    Error Verify(std::shared_ptr<PublicKey> key, 
                const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& message) override;
};

// RSA PyCrypto验证器
class RSAPyCryptoVerifier : public Verifier {
public:
    Error Verify(std::shared_ptr<PublicKey> key, 
                const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& message) override;
};

// ECDSA验证器
class ECDSAVerifier : public Verifier {
public:
    Error Verify(std::shared_ptr<PublicKey> key, 
                const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& message) override;
};

// Ed25519验证器
class Ed25519Verifier : public Verifier {
public:
    Error Verify(std::shared_ptr<PublicKey> key, 
                const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& message) override;
};

} // namespace crypto
} // namespace notary