# Notary C++

这是一个C++实现的Notary项目，用于内容签名和管理。基于The Update Framework (TUF)，实现了一个最小化的Notary系统，可用于确保软件发布和内容分发的安全性。

## 依赖项

- C++17 或更高版本 (需要 std::filesystem 支持)
- OpenSSL 3.0+ (用于密码学操作)
- CLI11 (命令行解析)
- nlohmann/json (JSON处理)
- Catch2 (测试框架)

## 快速开始

### 构建

```bash
# 使用提供的脚本构建项目
./build.sh

# 或者手动构建
mkdir -p build && cd build
cmake ..
make
```

### 使用方法

当前已实现了基础的初始化功能：

```bash
# 基本初始化 (创建一个新的信任集合)
./build/bin/notary init <GUN>

# 使用调试模式查看详细信息
./build/bin/notary --debug init <GUN>

# 初始化并自动发布(功能待实现)
./build/bin/notary init <GUN> -p
```

## 功能说明

### 已实现的功能

#### 1. 仓库初始化 (Repository Initialization)

✅ 已完成仓库初始化的核心功能，可执行`notary init`命令初始化一个新的信任集合。具体包括：

- 创建Trusted Collection目录结构
- 自动生成所需的角色密钥(Root, Targets, Snapshot, Timestamp)
- 初始化TUF元数据文件
  - root.json - 包含所有角色的公钥和阈值信息
  - targets.json - 目标文件的元数据（当前为空）
  - snapshot.json - 包含其他元数据文件的哈希和版本信息
  - timestamp.json - 指向最新snapshot的元数据
- 支持配置服务器管理的角色（默认只有Timestamp由服务器管理）

#### 2. 密钥管理系统 (Key Management)

✅ 完整实现了密钥生成、存储和管理系统：

- 使用OpenSSL的EVP接口进行密码学操作
- 支持ECDSA密钥对生成和管理
- 基于AES-256-GCM的安全密钥加密
- 使用PBKDF2密钥派生函数从口令生成加密密钥
- 密钥角色分配管理
- 密钥ID生成和查找

密钥管理组件包括：
- `CryptoService` - 密钥服务主类
- `PublicKey`/`PrivateKey` - 密钥接口
- `ECDSAPublicKey`/`ECDSAPrivateKey` - ECDSA密钥实现
- `KeyStore` - 密钥存储和管理

#### 3. 存储系统 (Storage System)

✅ 完成了本地元数据存储功能：

- 文件系统元数据存储
- JSON元数据格式处理
- 支持读取、写入、更新操作
- 基于角色的文件命名策略

#### 4. 命令行界面 (CLI)

✅ 实现了基础的命令行接口：

- 使用CLI11库处理命令行参数
- 支持全局选项（--debug, --trust-dir, --server等）
- 实现init子命令及其参数处理
- 详细的错误报告和成功消息

### 实现细节

仓库初始化的流程：

1. 解析命令行参数
2. 加载配置（信任目录、服务器URL等）
3. 创建仓库对象，设置GUN
4. 生成根密钥（如果没有提供）
5. 初始化各角色
6. 创建并签名TUF元数据
7. 将元数据保存到信任目录

密钥加密流程：
1. 生成随机盐和IV
2. 使用PBKDF2从密码派生密钥
3. 使用AES-256-GCM加密私钥
4. 保存加密数据（盐+IV+标签+密文）

## 下一步开发计划

### 近期开发目标

1. **实现notary add命令**
   - 支持添加目标文件到Targets
   - 实现文件哈希计算
   - 更新相关元数据

2. **实现notary publish命令**
   - 实现元数据签名
   - 支持将更新后的元数据发布到远程服务器
   - 实现版本管理和冲突检测

3. **完善密钥管理**
   - 实现ED25519和RSA密钥支持
   - 支持密钥的导入导出
   - 实现磁盘持久化密钥存储

### 中期开发目标

1. **远程服务器集成**
   - 实现与远程Notary服务器的通信
   - 支持元数据同步
   - 实现身份验证和授权

2. **安全性增强**
   - 实现更安全的密码管理
   - 支持硬件密钥存储
   - 增加完整性验证

3. **更多高级功能**
   - 委托角色（Delegated Roles）
   - 密钥轮换
   - 过期管理

## 项目结构

```
.
├── CMakeLists.txt           # 主CMake配置文件
├── include/                 # 头文件
│   └── notary/
│       ├── crypto/          # 加密相关
│       │   ├── crypto_service.hpp  # 加密服务
│       │   └── keys.hpp            # 密钥定义
│       ├── storage/         # 存储相关
│       │   └── metadata_store.hpp  # 元数据存储
│       ├── repository.hpp   # 仓库管理
│       └── types.hpp        # 类型定义
├── src/                     # 源文件
│   ├── main.cpp             # 主程序入口
│   ├── repository.cpp       # 仓库实现
│   ├── crypto/              # 加密实现
│   │   ├── crypto_service.cpp  # 加密服务实现
│   │   └── keys.cpp            # 密钥实现
│   ├── storage/             # 存储实现
│   │   └── metadata_store.cpp  # 元数据存储实现
│   └── CMakeLists.txt       # 源文件CMake配置
└── test/                    # 测试文件
    ├── repository_test.cpp  # 仓库测试
    └── CMakeLists.txt       # 测试CMake配置
```

## 开发指南

1. **代码规范**
   - 使用现代C++特性(C++17)
   - 遵循SOLID原则
   - 使用智能指针管理内存
   - 使用Result<T>和Error类处理错误

2. **安全考虑**
   - 使用OpenSSL的EVP接口
   - 安全的密钥存储和管理
   - 输入验证和安全检查

3. **贡献流程**
   - Fork仓库并创建功能分支
   - 添加测试用例
   - 确保代码通过所有测试
   - 提交PR并等待审核

## 已知问题

1. 当前使用了一些OpenSSL 3.0中已弃用的函数，未来将迁移到新API
2. 密钥目前仅存储在内存中，程序结束后不会保存
3. 某些平台上可能存在std::filesystem兼容性问题

## 许可证

MIT 