#!/bin/bash
set -e

# 创建测试数据目录
TEST_DIR=./tmp/notary-test
mkdir -p $TEST_DIR/example.com/_trust/tuf

# 创建测试数据
echo '{"signed":{"_type":"root","version":1,"expires":"2030-01-01T00:00:00Z","keys":{},"roles":{}},"signatures":[]}' > $TEST_DIR/example.com/_trust/tuf/1.root.json
echo '{"signed":{"_type":"targets","version":1,"expires":"2030-01-01T00:00:00Z","targets":{}},"signatures":[]}' > $TEST_DIR/example.com/_trust/tuf/1.targets.json
echo '{"signed":{"_type":"snapshot","version":1,"expires":"2030-01-01T00:00:00Z","meta":{}},"signatures":[]}' > $TEST_DIR/example.com/_trust/tuf/1.snapshot.json
echo '{"signed":{"_type":"timestamp","version":1,"expires":"2030-01-01T00:00:00Z","meta":{}},"signatures":[]}' > $TEST_DIR/example.com/_trust/tuf/1.timestamp.json

# 创建链接
ln -f $TEST_DIR/example.com/_trust/tuf/1.root.json $TEST_DIR/example.com/_trust/tuf/root.json
ln -f $TEST_DIR/example.com/_trust/tuf/1.targets.json $TEST_DIR/example.com/_trust/tuf/targets.json
ln -f $TEST_DIR/example.com/_trust/tuf/1.snapshot.json $TEST_DIR/example.com/_trust/tuf/snapshot.json
ln -f $TEST_DIR/example.com/_trust/tuf/1.timestamp.json $TEST_DIR/example.com/_trust/tuf/timestamp.json

# 计算校验和
ROOT_CHECKSUM=$(shasum -a 256 $TEST_DIR/example.com/_trust/tuf/1.root.json | cut -d' ' -f1)
cp $TEST_DIR/example.com/_trust/tuf/1.root.json $TEST_DIR/example.com/_trust/tuf/root.$ROOT_CHECKSUM.json

echo "测试数据已准备完成，位于: $TEST_DIR"
echo "Root校验和: $ROOT_CHECKSUM"

echo "=== 测试指南 ==="
echo "1. 启动服务器:"
echo "   ./notary-server --log-level=debug --log-format=text"
echo ""
echo "2. 测试获取指定版本元数据:"
echo "   curl -v http://localhost:4443/v2/example.com/_trust/tuf/1.root.json"
echo ""
echo "3. 其他测试命令:"
echo "   curl -v http://localhost:4443/v2/example.com/_trust/tuf/1.targets.json"
echo "   curl -v http://localhost:4443/v2/example.com/_trust/tuf/1.snapshot.json"
echo "   curl -v http://localhost:4443/v2/example.com/_trust/tuf/1.timestamp.json" 