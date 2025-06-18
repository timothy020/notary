# Trust Pinning 使用说明

## 概述

Trust Pinning（信任锚定）是Notary系统中用于验证证书信任的机制。本C++实现基于Go版本的notary trust pinning功能，目前仅实现了TOFU（Trust On First Use）模式。

## 核心组件

### 1. TrustPinConfig

Trust Pin配置类，用于配置信任锚定策略：

```cpp
class TrustPinConfig {
public:
    // CA映射：GUN前缀到CA文件路径 (暂未实现)
    std::map<std::string, std::string> ca;
    
    // 证书映射：GUN到证书ID列表 (暂未实现)  
    std::map<std::string, std::vector<std::string>> certs;
    
    // 是否禁用TOFU (Trust On First Use)
    bool disableTOFU = false;
};
```

### 2. CertChecker

证书检查器函数类型，用于验证证书：

```cpp
using CertChecker = std::function<bool(
    const std::shared_ptr<data::Certificate>& leafCert,
    const std::vector<std::shared_ptr<data::Certificate>>& intCerts
)>;
```

### 3. TrustPinChecker

Trust Pin检查器类，提供不同的检查模式：

```cpp
class TrustPinChecker {
public:
    // TOFU检查 - 当前已实现
    bool tofusCheck(...) const;
    
    // 证书检查 - 暂未实现
    bool certsCheck(...) const;
    
    // CA检查 - 暂未实现  
    bool caCheck(...) const;
};
```

## 当前实现功能

### TOFU（Trust On First Use）

TOFU是一种简单的信任策略，在首次遇到证书时选择信任该证书。

**特点：**
- 总是返回`true`，表示信任所有证书
- 适用于开发和测试环境
- 不提供强安全保证，但使用简单

**使用方式：**

```cpp
// 1. 创建配置
TrustPinConfig config;
config.disableTOFU = false;  // 启用TOFU

// 2. 创建GUN
data::GUN gun("docker.com/library/hello-world");

// 3. 创建检查器
auto certChecker = NewTrustPinChecker(config, gun, true);

// 4. 执行检查
bool isValid = certChecker(leafCert, intCerts);
```

## 工作流程

1. **配置创建**：创建`TrustPinConfig`对象并设置相关参数
2. **检查器创建**：调用`NewTrustPinChecker()`函数创建证书检查器
3. **策略选择**：根据配置自动选择合适的验证策略：
   - 如果有证书配置：使用证书检查（暂未实现）
   - 如果有CA配置：使用CA检查（暂未实现）
   - 默认：使用TOFU检查
4. **证书验证**：调用返回的检查器函数进行证书验证

## 配置选项说明

### disableTOFU

- **类型**：`bool`
- **默认值**：`false`
- **说明**：是否禁用TOFU模式
- **注意**：如果设置为`true`且是首次引导（`firstBootstrap=true`），在没有其他配置的情况下会抛出异常

## 错误处理

系统会在以下情况抛出异常：

1. **禁用TOFU且首次引导**：当`disableTOFU=true`且`firstBootstrap=true`时，如果没有其他有效配置
2. **功能未实现**：当尝试使用证书检查或CA检查功能时

## 未来计划

将来会实现以下功能：

1. **证书检查模式**：基于预配置的证书ID列表进行验证
2. **CA检查模式**：基于CA证书链进行验证
3. **通配符匹配**：支持GUN的通配符匹配
4. **CA文件加载**：从文件系统加载CA证书

## 示例代码

完整的使用示例请参考：`src/tuf/trustpinning_example.cpp`

## 与Go版本的对应关系

| Go版本 | C++版本 | 实现状态 |
|--------|---------|----------|
| `TrustPinConfig` | `TrustPinConfig` | ✅ 已实现 |
| `CertChecker` | `CertChecker` | ✅ 已实现 |
| `trustPinChecker` | `TrustPinChecker` | ✅ 已实现 |
| `NewTrustPinChecker` | `NewTrustPinChecker` | ✅ 已实现 |
| `tofusCheck` | `tofusCheck` | ✅ 已实现 |
| `certsCheck` | `certsCheck` | ❌ 暂未实现 |
| `caCheck` | `caCheck` | ❌ 暂未实现 |
| `wildcardMatch` | `wildcardMatch` | ❌ 暂未实现 |
| `getPinnedCAFilepathByPrefix` | `getPinnedCAFilepathByPrefix` | ❌ 暂未实现 |

## 安全考虑

- **TOFU模式**：仅适用于开发和测试环境，生产环境建议使用证书或CA检查模式
- **输入验证**：建议在使用前验证GUN和证书的有效性
- **错误处理**：妥善处理可能的异常情况 