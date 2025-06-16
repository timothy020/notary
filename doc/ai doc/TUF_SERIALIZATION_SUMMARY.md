# TUF 序列化功能实现总结

## 概述

本文档总结了为 C++ Notary 项目中的 `repo.hpp` 添加的 JSON 序列化功能，这些功能参考了 Go 版本 `types.go` 的实现方式。

## 新增的结构体和功能

### 1. 签名相关结构体

#### `Signature` 结构体
- **功能**: 表示 TUF 元数据的数字签名
- **字段**:
  - `KeyID`: 签名密钥的标识符
  - `Method`: 签名算法（如 "ecdsa"）
  - `Sig`: 签名数据（二进制）
  - `IsValid`: 运行时验证标记（不序列化）
- **序列化方法**:
  - `toJson()`: 转换为 JSON 格式
  - `fromJson()`: 从 JSON 解析

#### `SignedCommon` 结构体
- **功能**: TUF 元数据的通用字段
- **字段**:
  - `Type`: 元数据类型（如 "root", "targets"）
  - `Expires`: 过期时间
  - `Version`: 版本号
- **序列化方法**:
  - `toJson()`: 转换为 JSON 格式
  - `fromJson()`: 从 JSON 解析

### 2. 文件元数据结构体

#### `FileMeta` 结构体
- **功能**: 表示文件的元数据信息
- **字段**:
  - `Length`: 文件大小
  - `Hashes`: 文件哈希值映射（算法名 -> 哈希值）
  - `Custom`: 自定义数据（JSON 格式）
- **序列化方法**:
  - `toJson()`: 转换为 JSON 格式
  - `fromJson()`: 从 JSON 解析
  - `equals()`: 比较两个 FileMeta 是否相等

### 3. 委托相关结构体

#### `DelegationRole` 类
- **功能**: 表示委托角色信息
- **字段**:
  - `BaseRoleInfo`: 基础角色信息
  - `Paths`: 委托路径列表
  - `Name`: 角色名称
- **方法**:
  - `CheckPaths()`: 检查路径是否匹配
  - `toJson()`: 转换为 JSON 格式
  - `fromJson()`: 从 JSON 解析

#### `Delegations` 结构体
- **功能**: 表示委托信息集合
- **字段**:
  - `Keys`: 委托密钥映射
  - `Roles`: 委托角色列表
- **序列化方法**:
  - `toJson()`: 转换为 JSON 格式
  - `fromJson()`: 从 JSON 解析

### 4. TUF 元数据类

所有 TUF 元数据类（`SignedRoot`, `SignedTargets`, `SignedSnapshot`, `SignedTimestamp`）都添加了：

#### 新增字段
- `Common`: 通用元数据字段
- `Signatures`: 签名列表

#### 新增方法
- `toJson()`: 序列化为 JSON（仅 signed 部分）
- `fromJson()`: 从 JSON 反序列化
- `toSignedJson()`: 序列化为完整的带签名 JSON
- `Serialize()`: 序列化为字节数组
- `Deserialize()`: 从字节数组反序列化

## 辅助功能

### 1. 角色名称转换
- `roleNameToString()`: 将 RoleName 枚举转换为字符串
- `stringToRoleName()`: 将字符串转换为 RoleName 枚举

### 2. 时间格式转换
- `timeToISO8601()`: 将时间点转换为 ISO8601 格式字符串
- `iso8601ToTime()`: 将 ISO8601 字符串转换为时间点

### 3. Base64 编码
- `base64Encode()`: 将二进制数据编码为 Base64 字符串
- `base64Decode()`: 将 Base64 字符串解码为二进制数据

## JSON 格式兼容性

实现的 JSON 格式与 TUF 规范兼容，主要结构如下：

### Root 元数据
```json
{
  "signed": {
    "_type": "root",
    "version": 1,
    "expires": "2024-12-31T23:59:59Z",
    "keys": {
      "key_id": {
        "keytype": "ecdsa",
        "keyval": {
          "public": "base64_encoded_public_key"
        }
      }
    },
    "roles": {
      "root": {
        "threshold": 1,
        "keyids": ["key_id"]
      }
    }
  },
  "signatures": [
    {
      "keyid": "key_id",
      "method": "ecdsa",
      "sig": "base64_encoded_signature"
    }
  ]
}
```

### Targets 元数据
```json
{
  "signed": {
    "_type": "targets",
    "version": 1,
    "expires": "2024-12-31T23:59:59Z",
    "targets": {
      "file.txt": {
        "length": 1024,
        "hashes": {
          "sha256": "base64_encoded_hash"
        }
      }
    }
  },
  "signatures": [...]
}
```

## 实现特点

### 1. 类型安全
- 使用强类型枚举和结构体
- 编译时类型检查
- 避免运行时类型错误

### 2. 错误处理
- 使用异常处理机制
- 提供详细的错误信息
- 优雅的错误恢复

### 3. 内存管理
- 使用智能指针管理内存
- 避免内存泄漏
- RAII 原则

### 4. 性能优化
- 避免不必要的数据拷贝
- 使用移动语义
- 高效的 JSON 处理

## 使用示例

```cpp
// 创建 Root 元数据
auto root = std::make_shared<SignedRoot>();
root->Common.Type = "root";
root->Common.Version = 1;
root->Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24);

// 序列化为 JSON
json rootJson = root->toSignedJson();
std::string jsonStr = rootJson.dump();

// 序列化为字节数组
std::vector<uint8_t> data = root->Serialize();

// 反序列化
auto newRoot = std::make_shared<SignedRoot>();
bool success = newRoot->Deserialize(data);
```

## 注意事项

1. **密钥处理**: 密钥的序列化和反序列化需要与 `CryptoService` 配合
2. **哈希计算**: 文件哈希值需要在添加目标时计算
3. **签名验证**: 反序列化后需要验证签名的有效性
4. **时区处理**: 时间格式统一使用 UTC
5. **编码格式**: 二进制数据统一使用 Base64 编码

## 后续工作

1. 完善密钥的序列化和反序列化逻辑
2. 实现完整的签名验证功能
3. 添加更多的错误检查和验证
4. 优化性能和内存使用
5. 添加单元测试覆盖所有序列化功能 