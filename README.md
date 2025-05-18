# Notary C++

这是一个C++实现的Notary项目，用于内容签名和管理。基于The Update Framework (TUF)，实现了一个最小化的Notary系统，可用于确保软件发布和内容分发的安全性。

## 依赖项

- C++17 或更高版本 (需要 std::filesystem 支持)
- OpenSSL 3.0+ (用于密码学操作)
- CLI11 (命令行解析)
- nlohmann/json (JSON处理)
- Catch2 (测试框架, 需要版本3.x)
- UUID库 (用于生成唯一标识符)

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

目前已实现核心功能：

```bash
# 初始化信任集合
./bin/notary init <GUN>

# 添加目标文件
./bin/notary add <GUN> <TARGET_NAME> <TARGET_PATH> [--custom <CUSTOM_DATA_FILE>]

# 发布更改
./bin/notary publish <GUN>

# 使用调试模式查看详细信息
./bin/notary --debug <COMMAND>

# 初始化并自动发布
./bin/notary init <GUN> -p
```

## Ubuntu 22.04部署指南

### 1. 安装基础依赖项

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev uuid-dev
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
# 基本用法
./bin/notary init myproject

# 添加目标文件
./bin/notary add myproject mytarget /path/to/file

# 发布更改
./bin/notary publish myproject
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
   sudo apt install -y libssl-dev uuid-dev nlohmann-json3-dev
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

✅ 已完成仓库初始化的核心功能，可执行`notary init`命令初始化一个新的信任集合。具体包括：

- 创建Trusted Collection目录结构
- 自动生成所需的角色密钥(Root, Targets, Snapshot, Timestamp)
- 初始化TUF元数据文件
  - root.json - 包含所有角色的公钥和阈值信息
  - targets.json - 目标文件的元数据（当前为空）
  - snapshot.json - 包含其他元数据文件的哈希和版本信息
  - timestamp.json - 指向最新snapshot的元数据
- 支持配置服务器管理的角色（默认只有Timestamp由服务器管理）

#### 2. 目标管理 (Target Management)

✅ 实现了`notary add`命令，用于添加目标文件到信任集合：

- 支持添加任意文件作为可信目标
- 自动计算文件的哈希值（SHA-256和SHA-512）
- 支持添加自定义元数据
- 使用changelist机制跟踪待应用的更改
- 支持指定目标角色和委托角色

#### 3. 发布管理 (Publish Management)

✅ 实现了`notary publish`命令，用于将待处理的更改应用到元数据并发布：

- 将changelist中的更改应用到targets元数据
- 更新元数据版本号和过期时间
- 自动处理元数据签名
- 清理已应用的changelist
- 支持本地发布

#### 4. 密钥管理系统 (Key Management)

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

#### 5. Changelist机制 (Changelist Mechanism)

✅ 实现了类似Go版本的changelist功能：

- 跟踪对元数据的待处理更改
- 将更改保存为JSON格式的.change文件
- 支持添加、删除、更新操作
- 提供按时间戳排序的变更列表
- 在发布时应用所有待处理的更改

#### 6. 存储系统 (Storage System)

✅ 完成了本地元数据存储功能：

- 文件系统元数据存储
- JSON元数据格式处理
- 支持读取、写入、更新操作
- 基于角色的文件命名策略

#### 7. 命令行界面 (CLI)

✅ 实现了完整的命令行接口：

- 使用CLI11库处理命令行参数
- 支持全局选项（--debug, --trust-dir, --server等）
- 实现init, add, publish子命令及其参数处理
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

添加目标的流程：
1. 解析命令行参数（目标名称、路径等）
2. 读取目标文件并计算哈希
3. 创建Target对象和元数据
4. 生成changelist记录
5. 保存更改到.change文件

发布流程：
1. 获取当前targets元数据
2. 读取并解析changelist
3. 应用changelist更改到targets元数据
4. 更新元数据版本和过期时间
5. 签名并保存更新后的元数据
6. 清除已应用的changelist

密钥加密流程：
1. 生成随机盐和IV
2. 使用PBKDF2从密码派生密钥
3. 使用AES-256-GCM加密私钥
4. 保存加密数据（盐+IV+标签+密文）

## 下一步开发计划

### 近期开发目标

1. **远程服务器支持**
   - 实现与远程Notary服务器的通信
   - 支持远程发布元数据
   - 支持元数据同步和拉取

2. **委托角色支持**
   - 实现委托路径查找
   - 支持嵌套委托
   - 实现阈值签名验证

3. **完善密钥管理**
   - 实现ED25519和RSA密钥支持
   - 支持密钥的导入导出
   - 实现磁盘持久化密钥存储

### 中期开发目标

1. **安全增强**
   - 实现更安全的密码管理
   - 支持硬件密钥存储
   - 增加完整性验证

2. **更多高级功能**
   - 密钥轮换
   - 过期管理
   - 自动更新和一致性检查

3. **工具与互操作性**
   - 与Docker/OCI兼容性
   - 添加验证工具
   - 与其他TUF实现的互操作性

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