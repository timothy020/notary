# C++ PassRetriever 使用说明

## 概述

C++ PassRetriever 是模仿 Go 语言版本 notary 项目中的 `passphrase` 包实现的密码获取器。它提供了安全的密码输入、验证、缓存等功能，主要用于TUF密钥的密码管理。

## 功能特性

### 核心功能
- **安全密码输入**: 在终端环境下禁用回显，保护密码输入安全
- **密码验证**: 创建新密钥时验证密码强度（最少8位）
- **密码确认**: 创建新密钥时要求重复输入密码确认
- **密码缓存**: 在同一会话中缓存已输入的密码，避免重复输入
- **别名映射**: 支持为不同角色配置显示别名
- **错误处理**: 完整的错误处理机制，包括重试逻辑

### 支持的使用场景
1. **交互式密码输入**: 在终端中提示用户输入密码
2. **非交互式模式**: 从环境变量或文件读取密码
3. **测试模式**: 使用常量密码进行自动化测试
4. **自定义输入输出**: 支持指定输入输出流

## API 接口

### 主要类型定义

```cpp
// PassRetriever 函数类型
using PassRetriever = std::function<std::tuple<std::string, bool, Error>(
    const std::string& keyName,   // 密钥名称
    const std::string& alias,     // 角色别名
    bool createNew,               // 是否创建新密钥
    int numAttempts              // 尝试次数
)>;
```

### 工厂函数

#### 1. PromptRetriever()
创建一个标准的提示型密码获取器，自动检查终端状态。

```cpp
auto retriever = notary::passphrase::PromptRetriever();
auto [password, giveup, error] = retriever("keyname", "root", true, 0);
```

#### 2. PromptRetrieverWithInOut()
创建指定输入输出流的密码获取器，支持自定义别名映射。

```cpp
std::map<std::string, std::string> aliasMap = {
    {"root", "根密钥"},
    {"targets", "目标密钥"}
};

auto retriever = notary::passphrase::PromptRetrieverWithInOut(
    &std::cin, &std::cout, aliasMap);
```

#### 3. ConstantRetriever()
创建常量密码获取器，主要用于测试或自动化场景。

```cpp
auto retriever = notary::passphrase::ConstantRetriever("my_secret_password");
```

## 使用示例

### 基本使用

```cpp
#include "notary/passRetriever/passRetriever.hpp"

// 创建密码获取器
auto retriever = notary::passphrase::PromptRetriever();

// 获取root角色的新密钥密码
auto [password, giveup, error] = retriever("root_key_id", "root", true, 0);

if (!error.hasError()) {
    std::cout << "成功获取密码，长度: " << password.length() << std::endl;
} else {
    std::cout << "获取密码失败: " << error.what() << std::endl;
}
```

### 使用别名映射

```cpp
// 配置中文别名
std::map<std::string, std::string> aliasMap = {
    {"root", "根密钥"},
    {"targets", "目标密钥"},
    {"snapshot", "快照密钥"},
    {"timestamp", "时间戳密钥"}
};

auto retriever = notary::passphrase::PromptRetrieverWithInOut(
    &std::cin, &std::cout, aliasMap);

// 用户将看到中文提示："Enter passphrase for new 根密钥 key with ID abc1234: "
auto [password, giveup, error] = retriever("abc1234567", "root", true, 0);
```

### 测试场景

```cpp
// 模拟用户输入
std::istringstream input("mypassword123\nmypassword123\n");
std::ostringstream output;

auto retriever = notary::passphrase::PromptRetrieverWithInOut(&input, &output);
auto [password, giveup, error] = retriever("test_key", "root", true, 0);

// 检查输出内容
std::cout << output.str() << std::endl;
```

## 错误处理

PassRetriever 提供了完整的错误处理机制：

### 错误类型
- **ErrTooShort**: 密码长度不足（少于8位）
- **ErrDontMatch**: 两次输入的密码不匹配
- **ErrTooManyAttempts**: 尝试次数过多（超过3次）
- **ErrNoInput**: 没有有效的输入方法

### 错误处理示例

```cpp
auto [password, giveup, error] = retriever("key_id", "root", true, 0);

if (error.hasError()) {
    if (giveup) {
        std::cout << "用户放弃输入或达到最大尝试次数" << std::endl;
    } else {
        std::cout << "错误: " << error.what() << std::endl;
        // 可以重试或采取其他措施
    }
}
```

## 安全特性

### 密码输入安全
- 在终端环境下自动禁用回显，防止密码显示
- 非终端环境下直接读取输入流
- 输入完成后立即恢复终端设置

### 密码验证
- 新密钥密码最少8位长度要求
- 创建新密钥时要求重复输入确认
- 密码不匹配时给出明确提示

### 缓存机制
- 按角色别名缓存密码，避免重复输入
- 缓存仅在同一个 retriever 实例的生命周期内有效
- 提供安全的内存管理

## 与Go版本的对应关系

| Go 功能 | C++ 实现 | 说明 |
|---------|----------|------|
| `PassRetriever` 函数类型 | `PassRetriever` using 声明 | 完全对应 |
| `boundRetriever` 结构体 | `BoundRetriever` 类 | 完全对应 |
| `PromptRetriever()` | `PromptRetriever()` | 完全对应 |
| `PromptRetrieverWithInOut()` | `PromptRetrieverWithInOut()` | 完全对应 |
| `ConstantRetriever()` | `ConstantRetriever()` | 完全对应 |
| `GetPassphrase()` | `GetPassphrase()` | 完全对应 |
| 错误类型 | 继承自 `PassphraseError` 的错误类 | 改为异常类型 |

## 编译要求

- C++11 或更高版本
- POSIX 兼容系统（用于终端操作）
- 依赖 `notary/types.hpp` 中的 `Error` 类型

## 注意事项

1. **线程安全**: 当前实现不是线程安全的，多线程使用时需要外部同步
2. **平台兼容性**: 终端操作使用了POSIX API，主要支持Unix-like系统
3. **内存管理**: 使用了 `std::shared_ptr` 管理 `BoundRetriever` 实例
4. **错误传播**: 错误通过返回值传播，而不是异常 