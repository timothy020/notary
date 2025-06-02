# Notary C++

这是一个C++实现的Notary项目，用于内容签名和管理。基于The Update Framework (TUF)，实现了一个最小化的Notary系统，可用于确保软件发布和内容分发的安全性。

## 依赖项

- C++17 或更高版本 (需要 std::filesystem 支持)
- OpenSSL 3.0+ (用于密码学操作)
- CLI11 (命令行解析)
- nlohmann/json (JSON处理)
- Catch2 (测试框架, 需要版本3.x)
- UUID库 (用于生成唯一标识符)
- libcurl (用于HTTP通信)

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

目前已实现完整的Notary客户端功能：

```bash
# 初始化信任集合
./bin/notary init <GUN> [--publish]

# 添加目标文件
./bin/notary add <GUN> <TARGET_NAME> <TARGET_PATH> [--custom <CUSTOM_DATA_FILE>] [--publish]

# 发布更改到远程服务器
./bin/notary publish <GUN>

# 验证目标文件
./bin/notary verify <GUN> <TARGET_NAME> <TARGET_FILE>

# 删除信任数据
./bin/notary delete <GUN> [--remote]

# 使用调试模式查看详细信息
./bin/notary --debug <COMMAND>

# 指定信任目录和服务器
./bin/notary --trust-dir /path/to/trust --server https://notary.example.com <COMMAND>
```

## Ubuntu 22.04部署指南

### 1. 安装基础依赖项

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev uuid-dev libcurl4-openssl-dev
```

### 2. 安装JSON库

```bash
sudo apt install -y nlohmann-json3-dev
```

### 3. 安装CLI11库

```bash
# 方法1: 使用apt安装(如果可用)
sudo apt install -y libcli11-dev

# 方法2: 从源码安装
git clone https://github.com/CLIUtils/CLI11.git
cd CLI11
mkdir build && cd build
cmake ..
sudo make install
cd ../..
```

### 4. 安装Catch2 v3

```bash
# 首先移除系统上已安装的Catch2 v2(如果存在)
sudo apt remove catch2 libcatch2-dev

# 从源码安装Catch2 v3
git clone https://github.com/catchorg/Catch2.git
cd Catch2
git checkout v3.4.0  # 使用最新的v3.x稳定版本
mkdir build && cd build
cmake -DBUILD_TESTING=OFF ..
sudo make install
sudo ldconfig  # 更新共享库缓存
cd ../..
```

### 5. 克隆和构建项目

```bash
# 克隆项目(如果您还没有代码)
# git clone <repository-url>
# cd <repository-directory>

# 构建项目
cd cproject
mkdir -p build
cd build
cmake ..
make -j$(nproc)
cd ..
```

### 6. 运行程序

```bash
# 基本用法示例
./bin/notary init myproject

# 添加目标文件
./bin/notary add myproject mytarget /path/to/file

# 发布更改
./bin/notary publish myproject

# 验证文件
./bin/notary verify myproject mytarget /path/to/file

# 删除信任数据
./bin/notary delete myproject
./bin/notary delete myproject --remote
```

### 7. 常见问题解决

1. **CMake找不到Catch2**: 

   确保已安装Catch2 v3并指定Catch2目录:
   ```bash
   cmake .. -DCatch2_DIR=/usr/local/lib/cmake/Catch2
   ```

2. **编译时缺少头文件**:

   确保所有依赖都已安装:
   ```bash
   sudo apt install -y libssl-dev uuid-dev nlohmann-json3-dev libcurl4-openssl-dev
   ```

3. **OpenSSL版本兼容性警告**:

   这是正常的，项目使用了一些已废弃API，暂时不影响功能。

4. **权限问题**:

   如果脚本无法执行:
   ```bash
   chmod +x build.sh
   ```

## 功能说明

### 已实现的功能

#### 1. 仓库初始化 (Repository Initialization)

✅ **完全实现** - 可执行`notary init`命令初始化一个新的信任集合：

- 创建Trusted Collection目录结构
- 自动生成所需的角色密钥(Root, Targets, Snapshot, Timestamp)
- 初始化TUF元数据文件
  - root.json - 包含所有角色的公钥和阈值信息
  - targets.json - 目标文件的元数据（当前为空）
  - snapshot.json - 包含其他元数据文件的哈希和版本信息
- 支持配置服务器管理的角色（默认只有Timestamp由服务器管理）
- 支持自动发布 (`--publish` 标志)
- 兼容Go语言版本的notary实现

#### 2. 目标管理 (Target Management)

✅ **完全实现** - `notary add`命令，用于添加目标文件到信任集合：

- 支持添加任意文件作为可信目标
- 自动计算文件的哈希值（SHA-256和SHA-512）
- 支持添加自定义元数据 (`--custom` 参数)
- 使用changelist机制跟踪待应用的更改
- 支持指定目标角色和委托角色 (`--roles` 参数)
- 支持自动发布 (`--publish` 标志)
- 完整的错误处理和验证

#### 3. 发布管理 (Publish Management)

✅ **完全实现** - `notary publish`命令，支持本地和远程发布：

- 将changelist中的更改应用到targets元数据
- 自动更新元数据版本号和过期时间
- 完整的元数据签名流程
- 支持远程服务器发布（使用HTTP multipart/form-data）
- 使用SetMulti批量上传优化性能
- 自动处理服务器管理的角色（Timestamp自动生成）
- 清理已应用的changelist
- 原子性操作保证一致性

#### 4. 目标验证 (Target Verification)

✅ **新增功能** - `notary verify`命令，验证目标文件的完整性：

- 从远程服务器获取最新的信任元数据
- 通过目标名称查找目标信息
- 支持委托角色的目标查找（使用WalkTargets机制）
- 验证文件哈希值（支持多种哈希算法）
- 检查文件大小匹配
- 完整的错误报告和成功确认
- 兼容Go语言版本的验证逻辑

#### 5. 信任数据删除 (Trust Data Deletion)

✅ **新增功能** - `notary delete`命令，删除本地和远程信任数据：

- 删除本地TUF仓库数据目录
- 支持远程删除 (`--remote` 标志)
- 使用DELETE HTTP请求删除远程元数据
- 完整的错误处理和日志记录
- 模仿Go语言版本的DeleteTrustData功能
- 支持部分删除（仅本地）和完全删除（本地+远程）

#### 6. 服务端支持 (Server-side Support)

✅ **新增功能** - 服务端DeleteHandler实现：

- 处理来自客户端的DELETE请求
- 从URL参数提取GUN信息
- 调用存储服务删除GUN相关的所有元数据
- 完整的错误处理和日志记录
- 模仿Go语言版本的服务端删除逻辑

#### 7. 密钥管理系统 (Key Management)

✅ **完全实现** - 完整的密钥生成、存储和管理系统：

- 使用OpenSSL的EVP接口进行密码学操作
- 支持ECDSA密钥对生成和管理
- 基于AES-256-GCM的安全密钥加密
- 使用PBKDF2密钥派生函数从口令生成加密密钥
- 密钥角色分配管理
- 密钥ID生成和查找
- 支持从远程服务器获取公钥

密钥管理组件包括：
- `CryptoService` - 密钥服务主类
- `PublicKey`/`PrivateKey` - 密钥接口
- `ECDSAPublicKey`/`ECDSAPrivateKey` - ECDSA密钥实现
- `KeyStore` - 密钥存储和管理

#### 8. Changelist机制 (Changelist Mechanism)

✅ **完全实现** - 类似Go版本的changelist功能：

- 跟踪对元数据的待处理更改
- 将更改保存为JSON格式的.change文件
- 支持添加、删除、更新操作
- 提供按时间戳排序的变更列表
- 在发布时应用所有待处理的更改
- 支持角色验证和多角色操作

#### 9. 存储系统 (Storage System)

✅ **完全实现** - 本地和远程元数据存储功能：

**本地存储：**
- 文件系统元数据存储
- JSON元数据格式处理
- 支持读取、写入、更新、删除操作
- 基于角色的文件命名策略

**远程存储：**
- 使用libcurl进行HTTP通信
- 支持GET请求获取元数据和密钥
- 支持POST请求上传元数据（单个和批量）
- 支持DELETE请求删除GUN数据
- 完整的HTTP状态码处理
- multipart/form-data格式支持

#### 10. 命令行界面 (CLI)

✅ **完全实现** - 完整的命令行接口：

- 使用CLI11库处理命令行参数
- 支持全局选项（--debug, --trust-dir, --server等）
- 实现所有子命令：init, add, publish, verify, delete
- 详细的参数验证和错误报告
- 丰富的成功和错误消息
- 支持密码参数和调试模式

#### 11. TUF元数据处理 (TUF Metadata Processing)

✅ **完全实现** - 完整的TUF规范实现：

- 支持所有TUF角色：Root, Targets, Snapshot, Timestamp
- 元数据版本管理和过期时间处理
- 数字签名验证和生成
- 委托机制支持（WalkTargets实现）
- 元数据一致性检查
- 服务器管理角色的自动处理

### 实现细节

**仓库初始化的流程：**

1. 解析命令行参数
2. 加载配置（信任目录、服务器URL等）
3. 创建仓库对象，设置GUN
4. 生成根密钥（如果没有提供）
5. 初始化各角色（本地和远程密钥获取）
6. 创建并签名TUF元数据
7. 将元数据保存到信任目录
8. 可选的自动发布到远程服务器

**添加目标的流程：**
1. 解析命令行参数（目标名称、路径等）
2. 读取目标文件并计算哈希（SHA-256, SHA-512）
3. 创建Target对象和FileMeta元数据
4. 生成changelist记录（支持多角色）
5. 保存更改到.change文件
6. 可选的自动发布

**发布流程：**
1. 更新TUF元数据（从远程获取最新版本）
2. 应用changelist到内存中的Repo对象
3. 检查并签名需要更新的角色
4. 使用SetMulti批量上传到远程服务器
5. 清除已应用的changelist
6. 完整的错误恢复机制

**验证流程：**
1. 从远程服务器获取最新元数据
2. 使用WalkTargets在委托层次中查找目标
3. 读取本地文件并计算哈希
4. 比较哈希值和文件大小
5. 报告验证结果

**删除流程：**
1. 删除本地TUF仓库数据目录
2. 可选删除远程数据（发送DELETE请求）
3. 完整的错误处理和日志记录

**密钥加密流程：**
1. 生成随机盐和IV
2. 使用PBKDF2从密码派生密钥
3. 使用AES-256-GCM加密私钥
4. 保存加密数据（盐+IV+标签+密文）

## 跨平台支持

项目已在以下平台测试通过：

- Ubuntu 22.04 LTS
- macOS Darwin 24.1.0
- Windows 10 (使用Visual Studio 2022)

## 与Go版本的兼容性

本C++实现严格遵循Go语言版本的notary实现，确保：

- 元数据格式完全兼容
- TUF规范严格遵循
- 网络协议兼容
- 文件存储格式兼容
- 命令行接口一致

## 下一步开发计划

### 近期开发目标

1. **完善委托角色支持**
   - 实现委托角色的创建和管理
   - 支持嵌套委托
   - 实现阈值签名验证
   - 支持野卡委托

2. **增强安全性**
   - 实现更安全的密码管理
   - 支持硬件密钥存储
   - 增加完整性验证
   - 添加防篡改机制

3. **性能优化**
   - 优化大文件处理
   - 改进网络通信效率
   - 增加缓存机制
   - 并发处理支持

### 中期开发目标

1. **更多密钥类型支持**
   - 实现ED25519和RSA密钥支持
   - 支持密钥的导入导出
   - 实现磁盘持久化密钥存储
   - 添加密钥轮换功能

2. **高级功能**
   - 密钥轮换和过期管理
   - 自动更新和一致性检查
   - 多签名支持
   - 离线签名支持

3. **工具与互操作性**
   - 与Docker/OCI兼容性
   - 添加验证工具
   - 与其他TUF实现的互操作性
   - 提供SDK和API接口

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
│       │   ├── metadata_store.hpp  # 元数据存储
│       │   └── key_storage.hpp     # 密钥存储
│       ├── changelist/      # 变更列表
│       │   └── changelist.hpp     # 变更列表管理
│       ├── tuf/            # TUF相关
│       │   ├── repo.hpp           # 仓库管理
│       │   └── builder.hpp        # 构建器
│       ├── utils/          # 工具类
│       │   ├── tools.hpp          # 工具函数
│       │   └── helpers.hpp        # 辅助函数
│       ├── server/         # 服务端
│       │   └── handlers/          # 请求处理器
│       ├── repository.hpp   # 仓库管理
│       └── types.hpp        # 类型定义
├── src/                     # 源文件
│   ├── main.cpp             # 主程序入口
│   ├── repository.cpp       # 仓库实现
│   ├── crypto/              # 加密实现
│   ├── storage/             # 存储实现
│   ├── changelist/          # 变更列表实现
│   ├── tuf/                # TUF实现
│   ├── utils/              # 工具实现
│   ├── server/             # 服务端实现
│   └── CMakeLists.txt       # 源文件CMake配置
└── test/                    # 测试文件
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
2. 密钥目前主要存储在本地文件系统中，未来将支持更安全的存储方式
3. 某些平台上可能存在std::filesystem兼容性问题，需要C++17编译器支持

## 许可证

MIT 