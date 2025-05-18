#!/bin/bash

# 创建构建目录
mkdir -p build

# 进入构建目录
cd build

# 配置项目
cmake ..

# 编译
make -j$(nproc)
