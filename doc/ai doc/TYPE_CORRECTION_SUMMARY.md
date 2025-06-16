# TUF 属性类型修正总结

## 概述

根据 Go 版本的 TUF 代码，我对 C++ 版本 `repo.hpp` 中的属性类型进行了重要修正，确保与 Go 版本的数据结构保持一致。

## 主要修正

### 1. SignedTargets 类型修正

**修正前：**
```cpp
class SignedTargets : public Signed {
public:
    std::map<std::string, std::vector<uint8_t>> Targets;  // 错误类型
    SignedCommon Common;
    // ...
};
```

**修正后：**
```cpp
class SignedTargets : public Signed {
public:
    std::map<std::string, FileMeta> Targets;  // Files类型：map[string]FileMeta
    Delegations Delegations;  // 委托信息
    SignedCommon Common;
    // ...
};
```

**对应 Go 代码：**
```go
type Targets struct {
    SignedCommon
    Targets     Files       `json:"targets"`      // Files = map[string]FileMeta
    Delegations Delegations `json:"delegations,omitempty"`
}
```

### 2. SignedSnapshot 类型修正

**修正前：**
```cpp
class SignedSnapshot : public Signed {
public:
    std::map<std::string, std::vector<uint8_t>> Meta;  // 错误类型
    SignedCommon Common;
    // ...
};
```

**修正后：**
```cpp
class SignedSnapshot : public Signed {
public:
    std::map<std::string, FileMeta> Meta;  // Files类型：map[string]FileMeta
    SignedCommon Common;
    // ...
};
```

**对应 Go 代码：**
```go
type Snapshot struct {
    SignedCommon
    Meta Files `json:"meta"`  // Files = map[string]FileMeta
}
```

### 3. SignedTimestamp 类型修正

**修正前：**
```cpp
class SignedTimestamp : public Signed {
public:
    std::map<std::string, std::vector<uint8_t>> Meta;  // 错误类型
    SignedCommon Common;
    // ...
};
```

**修正后：**
```cpp
class SignedTimestamp : public Signed {
public:
    std::map<std::string, FileMeta> Meta;  // Files类型：map[string]FileMeta
    SignedCommon Common;
    // ...
};
```

**对应 Go 代码：**
```go
type Timestamp struct {
    SignedCommon
    Meta Files `json:"meta"`  // Files = map[string]FileMeta
}
```

## 新增的结构体定义

为了支持正确的类型，我添加了以下结构体定义：

### FileMeta 结构体
```cpp
struct FileMeta {
    int64_t Length;
    std::map<std::string, std::vector<uint8_t>> Hashes;
    json Custom; // 可选的自定义数据
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
    
    // 比较方法
    bool equals(const FileMeta& other) const;
};
```

### DelegationRole 类
```cpp
class DelegationRole {
public:
    BaseRole BaseRoleInfo;
    std::vector<std::string> Paths;
    RoleName Name;
    
    bool CheckPaths(const std::string& path) const;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};
```

### Delegations 结构体
```cpp
struct Delegations {
    std::map<std::string, std::shared_ptr<PublicKey>> Keys;
    std::vector<DelegationRole> Roles;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};
```

## 头文件结构优化

为了解决类型依赖问题，我重新组织了头文件结构：

1. **类型定义顺序**：将 `FileMeta`、`DelegationRole`、`Delegations` 等基础类型定义移到前面
2. **前向声明**：保留必要的前向声明
3. **依赖关系**：确保所有类型在使用前都已定义

## 实现更新

相应地更新了以下实现：

### 1. JSON 序列化方法
- 更新了 `toJson()` 方法以正确处理 `FileMeta` 对象
- 修正了序列化逻辑以匹配 TUF 规范

### 2. 辅助函数
- 更新了 `NewSnapshot()` 和 `NewTimestamp()` 函数
- 修正了 `AddTarget()` 方法以创建正确的 `FileMeta` 对象

### 3. 新增方法
为各个类添加了新的方法：
- `SignedTargets::GetMeta()`、`AddTarget()`
- `SignedSnapshot::AddMeta()`、`GetMeta()`、`DeleteMeta()`
- `SignedTimestamp::GetSnapshot()`

## 与 Go 版本的对应关系

| Go 类型 | C++ 类型 | 说明 |
|---------|----------|------|
| `Files` | `std::map<std::string, FileMeta>` | 文件元数据映射 |
| `FileMeta` | `FileMeta` | 文件元数据结构 |
| `Delegations` | `Delegations` | 委托信息结构 |
| `DelegationRole` | `DelegationRole` | 委托角色类 |

## 编译验证

修正后的代码已通过编译验证，确保：
- 所有类型定义正确
- 依赖关系清晰
- 与 Go 版本保持一致的数据结构

这些修正确保了 C++ 版本的 TUF 实现与 Go 版本在数据结构层面的完全兼容性。 