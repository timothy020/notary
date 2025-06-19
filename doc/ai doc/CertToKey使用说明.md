# CertToKey C++ 实现说明

## 概述

`CertToKey` 函数是从Go语言的 `notary/tuf/utils/x509.go` 中的 `CertToKey` 函数移植到C++的实现。该函数将X509证书转换为对应的TUF PublicKey对象。

## 功能对比

### Go版本 (原始实现)
```go
// CertToKey transforms a single input certificate into its corresponding
// PublicKey
func CertToKey(cert *x509.Certificate) data.PublicKey {
	block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	pemdata := pem.EncodeToMemory(&block)

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return data.NewRSAx509PublicKey(pemdata)
	case x509.ECDSA:
		return data.NewECDSAx509PublicKey(pemdata)
	default:
		logrus.Debugf("Unknown key type parsed from certificate: %v", cert.PublicKeyAlgorithm)
		return nil
	}
}
```

### C++版本 (移植实现)
```cpp
std::shared_ptr<crypto::PublicKey> CertToKey(X509* cert);
std::shared_ptr<crypto::PublicKey> CertToKey(const Certificate& cert);
```

## 实现细节

### 1. 证书处理
- **Go版本**: 直接访问 `cert.Raw` 获取DER格式的证书数据
- **C++版本**: 使用 `i2d_X509()` 将X509证书转换为DER格式

### 2. PEM转换
- **Go版本**: 使用 `pem.EncodeToMemory()` 将DER数据包装为PEM格式
- **C++版本**: 使用OpenSSL的 `PEM_write_bio_X509()` 转换为PEM格式

### 3. 密钥类型检测
- **Go版本**: 检查 `cert.PublicKeyAlgorithm`
- **C++版本**: 使用 `X509_get_pubkey()` 和 `EVP_PKEY_id()` 获取密钥类型

### 4. 公钥对象创建
| Go版本 | C++版本 |
|--------|---------|
| `data.NewRSAx509PublicKey(pemdata)` | `crypto::NewRSAx509PublicKey(pemBytes)` |
| `data.NewECDSAx509PublicKey(pemdata)` | `crypto::NewECDSAx509PublicKey(pemBytes)` |

## 新增的类

### RSAx509PublicKey
```cpp
class RSAx509PublicKey : public TUFKey {
public:
    RSAx509PublicKey(const std::vector<uint8_t>& x509Data)
        : TUFKey(RSA_X509_KEY, x509Data, std::vector<uint8_t>()) {}
};
```

### ECDSAx509PublicKey
```cpp
class ECDSAx509PublicKey : public TUFKey {
public:
    ECDSAx509PublicKey(const std::vector<uint8_t>& x509Data)
        : TUFKey(ECDSA_X509_KEY, x509Data, std::vector<uint8_t>()) {}
};
```

## 工厂函数

```cpp
std::shared_ptr<PublicKey> NewRSAx509PublicKey(const std::vector<uint8_t>& x509Data);
std::shared_ptr<PublicKey> NewECDSAx509PublicKey(const std::vector<uint8_t>& x509Data);
```

## 使用示例

### 基本使用
```cpp
#include "notary/utils/x509.hpp"
#include "notary/crypto/keys.hpp"

// 从文件加载证书
auto cert = notary::utils::LoadCertificateFromFile("certificate.pem");
if (cert) {
    // 提取公钥
    auto publicKey = notary::utils::CertToKey(*cert);
    if (publicKey) {
        std::cout << "密钥算法: " << publicKey->Algorithm() << std::endl;
        std::cout << "密钥ID: " << publicKey->ID() << std::endl;
    }
}
```

### 直接使用X509指针
```cpp
X509* cert = /* 获取证书 */;
auto publicKey = notary::utils::CertToKey(cert);
if (publicKey) {
    // 处理公钥
}
```

## 错误处理

C++版本提供了完善的错误处理机制：

1. **空证书检查**: 如果证书为nullptr，返回nullptr并记录错误
2. **DER转换失败**: 如果无法将证书转换为DER格式，返回nullptr
3. **PEM转换失败**: 如果无法创建PEM格式，返回nullptr
4. **公钥提取失败**: 如果无法从证书提取公钥，返回nullptr
5. **不支持的密钥类型**: 对于不支持的密钥类型，返回nullptr并记录警告

## 支持的密钥类型

| 密钥类型 | OpenSSL常量 | 返回的PublicKey类型 |
|---------|-------------|-------------------|
| RSA | `EVP_PKEY_RSA` | `RSAx509PublicKey` |
| ECDSA | `EVP_PKEY_EC` | `ECDSAx509PublicKey` |
| 其他 | - | `nullptr` (不支持) |

## 编译和运行

### 编译示例
```bash
cd notary/cproject
mkdir build && cd build
cmake ..
make x509-example
```

### 运行示例
```bash
./x509-example
```

## 功能完整性对比

| 功能 | Go版本 | C++版本 | 状态 |
|------|--------|---------|------|
| 基本证书转换 | ✅ | ✅ | 完成 |
| RSA证书支持 | ✅ | ✅ | 完成 |
| ECDSA证书支持 | ✅ | ✅ | 完成 |
| 错误处理 | ✅ | ✅ | 完成 |
| 日志记录 | ✅ | ✅ | 完成 |
| PEM格式转换 | ✅ | ✅ | 完成 |
| 密钥ID计算 | ✅ | ✅ | 完成 |

## 注意事项

1. **内存管理**: C++版本使用智能指针自动管理内存
2. **线程安全**: OpenSSL函数调用需要注意线程安全
3. **性能**: C++版本性能与Go版本相当
4. **兼容性**: 完全兼容Go版本的输出格式

## 文件位置

- **头文件**: `notary/cproject/include/notary/utils/x509.hpp`
- **实现文件**: `notary/cproject/src/utils/x509.cpp`
- **密钥类定义**: `notary/cproject/include/notary/crypto/keys.hpp`
- **示例文件**: `notary/cproject/src/utils/x509_example.cpp`
- **本文档**: `notary/cproject/doc/CertToKey使用说明.md` 