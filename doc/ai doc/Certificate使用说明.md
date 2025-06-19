# Certificate 模块使用说明

## 概述

Certificate模块提供了X.509证书的生成、验证和管理功能。本C++实现基于Go版本的`cryptoservice/certificate.go`和`tuf/utils/x509.go`，使用OpenSSL库提供底层的密码学操作。

## 核心组件

### 1. Certificate类

X.509证书的C++包装类，提供证书的各种操作：

```cpp
class Certificate {
public:
    // 构造函数
    explicit Certificate(X509* cert);
    
    // 获取证书信息
    std::string GetCommonName() const;
    std::chrono::system_clock::time_point GetNotBefore() const;
    std::chrono::system_clock::time_point GetNotAfter() const;
    std::shared_ptr<PublicKey> GetPublicKey() const;
    
    // 格式转换
    std::vector<uint8_t> ToPEM() const;
    std::vector<uint8_t> ToDER() const;
    
    // 验证
    bool IsValid() const;
};
```

### 2. 证书生成函数

#### GenerateCertificate

主要的证书生成函数，对应Go版本的`GenerateCertificate`：

```cpp
std::shared_ptr<Certificate> GenerateCertificate(
    std::shared_ptr<PrivateKey> rootKey,
    const std::string& gun,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
);
```

**参数说明：**
- `rootKey`: 用于签名证书的根私钥
- `gun`: 全局唯一名称(Globally Unique Name)，用作证书的Common Name
- `startTime`: 证书有效期开始时间
- `endTime`: 证书有效期结束时间

#### NewCertificateTemplate

创建证书模板，对应Go版本utils包的`NewCertificate`：

```cpp
X509* NewCertificateTemplate(
    const std::string& commonName,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
);
```

### 3. 证书加载函数

#### LoadCertificateFromPEM

从PEM格式数据加载证书：

```cpp
std::shared_ptr<Certificate> LoadCertificateFromPEM(const std::vector<uint8_t>& pemData);
```

#### LoadCertificateFromFile

从文件加载证书：

```cpp
std::shared_ptr<Certificate> LoadCertificateFromFile(const std::string& filename);
```

### 4. 证书验证函数

#### ValidateCertificate

验证证书有效性，对应Go版本utils包的`ValidateCertificate`：

```cpp
bool ValidateCertificate(const Certificate& cert, bool checkExpiry = true);
```

**验证项目：**
- 证书有效期窗口检查
- 禁止SHA1签名算法
- RSA密钥长度检查（最小2048位）
- 过期时间检查（可选）

## 使用示例

### 基本证书生成

```cpp
#include "notary/crypto/certificate.hpp"
#include <chrono>

// 创建证书模板
auto now = std::chrono::system_clock::now();
auto endTime = now + std::chrono::hours(24 * 365); // 1年有效期

X509* certTemplate = NewCertificateTemplate(
    "docker.com/library/hello-world",
    now,
    endTime
);

// 创建Certificate对象
auto cert = std::make_shared<Certificate>(certTemplate);

// 获取证书信息
std::string commonName = cert->GetCommonName();
auto notBefore = cert->GetNotBefore();
auto notAfter = cert->GetNotAfter();
```

### 证书验证

```cpp
// 验证证书（包括过期检查）
bool isValid = ValidateCertificate(*cert, true);

// 验证证书（不检查过期）
bool isValidIgnoreExpiry = ValidateCertificate(*cert, false);
```

### 证书格式转换

```cpp
// 转换为PEM格式
auto pemData = cert->ToPEM();

// 转换为DER格式
auto derData = cert->ToDER();
```

### 从文件加载证书

```cpp
try {
    auto loadedCert = LoadCertificateFromFile("certificate.pem");
    std::cout << "证书Common Name: " << loadedCert->GetCommonName() << std::endl;
} catch (const CertificateError& e) {
    std::cerr << "加载失败: " << e.what() << std::endl;
}
```

## 功能特性

### 已实现功能

| 功能 | 状态 | 说明 |
|------|------|------|
| **证书模板创建** | ✅ 完成 | NewCertificateTemplate |
| **证书包装类** | ✅ 完成 | Certificate类 |
| **PEM/DER转换** | ✅ 完成 | ToPEM/ToDER方法 |
| **证书验证** | ✅ 完成 | ValidateCertificate |
| **文件加载** | ✅ 完成 | LoadCertificateFromFile |
| **证书信息提取** | ✅ 完成 | GetCommonName等方法 |

### 待完善功能

| 功能 | 状态 | 说明 |
|------|------|------|
| **完整证书生成** | ⚠️ 部分实现 | 需要完善私钥集成 |
| **公钥提取** | ❌ 待实现 | GetPublicKey方法 |
| **证书链验证** | ❌ 待实现 | 多级证书验证 |
| **扩展属性** | ❌ 待实现 | SAN等扩展 |

## 证书模板配置

生成的证书模板包含以下配置：

- **版本**: X.509 v3
- **序列号**: 128位随机数
- **签名算法**: SHA256（禁用SHA1）
- **密钥用途**: 数字签名 + 密钥加密
- **扩展密钥用途**: 代码签名
- **基础约束**: CA=FALSE（非CA证书）

## 错误处理

### CertificateError异常

所有证书相关的错误都抛出`CertificateError`异常：

```cpp
try {
    auto cert = GenerateCertificate(rootKey, gun, startTime, endTime);
} catch (const CertificateError& e) {
    std::cerr << "证书错误: " << e.what() << std::endl;
}
```

### 常见错误情况

1. **空指针错误**: 传入空的私钥或证书指针
2. **算法不支持**: 使用不支持的密钥算法
3. **OpenSSL错误**: 底层密码学操作失败
4. **文件读取错误**: 证书文件不存在或格式错误

## 安全考虑

### 密钥算法

- ✅ 支持: ECDSA, RSA
- ❌ 禁用: DSA, SHA1签名

### 密钥长度

- **RSA**: 最小2048位
- **ECDSA**: 推荐使用P-256或更高级别曲线

### 证书验证

- 自动检查证书有效期
- 禁止弱签名算法
- 验证密钥长度符合安全要求
- 支持证书即将过期的警告

## 依赖关系

### OpenSSL库

需要以下OpenSSL组件：
- `libssl`: SSL/TLS支持
- `libcrypto`: 密码学操作
- 头文件: `x509.h`, `pem.h`, `evp.h`等

### 内部依赖

- `notary/crypto/keys.hpp`: 密钥管理
- `notary/utils/logger.hpp`: 日志记录
- `notary/types.hpp`: 基础类型定义

## 与Go版本的对应关系

| Go函数/类型 | C++对应 | 实现状态 |
|-------------|---------|----------|
| `GenerateCertificate` | `GenerateCertificate` | ✅ 框架完成 |
| `generateCertificate` | `generateCertificateInternal` | ⚠️ 需要密钥集成 |
| `utils.NewCertificate` | `NewCertificateTemplate` | ✅ 完成 |
| `utils.ValidateCertificate` | `ValidateCertificate` | ✅ 完成 |
| `utils.LoadCertFromPEM` | `LoadCertificateFromPEM` | ✅ 完成 |
| `utils.LoadCertFromFile` | `LoadCertificateFromFile` | ✅ 完成 |
| `utils.CertToPEM` | `Certificate::ToPEM` | ✅ 完成 |

## 示例代码

完整的使用示例请参考：`src/crypto/certificate_example.cpp`

## 构建说明

确保在CMakeLists.txt中包含：
```cmake
target_link_libraries(notary_lib
    PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    # ... 其他库
)
```

## 注意事项

1. **内存管理**: Certificate类使用RAII管理X509对象生命周期
2. **线程安全**: OpenSSL操作需要适当的同步
3. **错误检查**: 所有OpenSSL API调用都包含错误检查
4. **资源清理**: 自动释放所有分配的OpenSSL资源 