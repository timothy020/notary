#include "notary/storage/memorystore.hpp"
#include "notary/types.hpp"

namespace notary {
namespace storage {

// MemoryStore 实现
Result<std::vector<uint8_t>> MemoryStore::Get(const std::string& name) {
    auto it = storage_.find(name);
    if (it == storage_.end()) {
        return Result<std::vector<uint8_t>>(Error("Key not found: " + name));
    }
    return Result<std::vector<uint8_t>>(it->second);
}

// GetSized 返回给定名称的数据，最多读取size字节
Result<std::vector<uint8_t>> MemoryStore::GetSized(const std::string& name, int64_t size) {
    auto it = storage_.find(name);
    if (it == storage_.end()) {
        return Result<std::vector<uint8_t>>(Error("Key not found: " + name));
    }
    
    const auto& data = it->second;
    
    // 如果size为NO_SIZE_LIMIT，返回完整数据
    if (size == NO_SIZE_LIMIT || size < 0) {
        return Result<std::vector<uint8_t>>(data);
    }
    
    // 如果数据大小超过限制，返回错误
    if (static_cast<int64_t>(data.size()) > size) {
        return Result<std::vector<uint8_t>>(Error("Data too large, potential malicious server attack"));
    }
    
    // 返回限制大小的数据
    int64_t readSize = std::min(static_cast<int64_t>(data.size()), size);
    std::vector<uint8_t> result(data.begin(), data.begin() + readSize);
    return Result<std::vector<uint8_t>>(std::move(result));
}

Error MemoryStore::Set(const std::string& name, const std::vector<uint8_t>& data) {
    storage_[name] = data;
    return Error(); // 成功
}

// SetMulti 在一次操作中设置多个键值对
Error MemoryStore::SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) {
    // 遍历map，对每个键值对调用Set方法
    for (const auto& pair : data) {
        Error err = Set(pair.first, pair.second);
        if (err.hasError()) {
            return err; // 如果任何Set操作失败，立即返回错误
        }
    }
    return Error(); // 成功
}

Error MemoryStore::Remove(const std::string& name) {
    storage_.erase(name);
    return Error(); // 成功
}

// RemoveAll 清空所有存储的数据
Error MemoryStore::RemoveAll() {
    storage_.clear();
    return Error(); // 成功
}

std::vector<std::string> MemoryStore::ListFiles() {
    std::vector<std::string> files;
    for (const auto& pair : storage_) {
        files.push_back(pair.first);
    }
    return files;
}

std::string MemoryStore::Location() const {
    return "memory";
}

} // namespace storage
} // namespace notary