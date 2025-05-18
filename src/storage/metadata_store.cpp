#include "notary/storage/metadata_store.hpp"
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <system_error>

namespace notary {
namespace storage {

namespace fs = std::filesystem;

MetadataStore::MetadataStore(const std::string& trustDir)
    : trustDir_(trustDir) {
    // 确保目录存在
    std::error_code ec;
    fs::create_directories(trustDir_, ec);
    if (ec) {
        // 记录错误但继续执行，因为目录可能已经存在
    }
}

Error MetadataStore::Set(const std::string& gun, 
                        const std::string& role, 
                        const json& data) {
    try {
        // 创建 GUN 目录
        std::string gunDir = trustDir_ + "/" + gun;
        std::error_code ec;
        fs::create_directories(gunDir, ec);
        if (ec) {
            return Error("Failed to create directory: " + gunDir + " - " + ec.message());
        }
        
        // 构建文件路径
        std::string filePath = getMetadataPath(gun, role);
        
        // 写入文件
        std::ofstream file(filePath);
        if (!file.is_open()) {
            return Error("Failed to open file for writing: " + filePath);
        }
        
        file << data.dump(2);
        file.close();
        
        return Error();
    } catch (const std::exception& e) {
        return Error("Failed to set metadata: " + std::string(e.what()));
    }
}

Result<json> MetadataStore::Get(const std::string& gun, 
                               const std::string& role) {
    try {
        std::string filePath = getMetadataPath(gun, role);
        
        // 检查文件是否存在
        std::error_code ec;
        if (!fs::exists(filePath, ec)) {
            if (ec) {
                return Result<json>(Error("Error checking file existence: " + ec.message()));
            }
            return Result<json>(Error("Metadata not found: " + filePath));
        }
        
        // 读取文件
        std::ifstream file(filePath);
        if (!file.is_open()) {
            return Result<json>(Error("Failed to open file: " + filePath));
        }
        
        json data;
        file >> data;
        return Result<json>(data);
    } catch (const std::exception& e) {
        return Result<json>(Error("Failed to get metadata: " + std::string(e.what())));
    }
}

Error MetadataStore::Remove(const std::string& gun, 
                          const std::string& role) {
    try {
        std::string filePath = getMetadataPath(gun, role);
        
        // 检查文件是否存在
        std::error_code ec;
        if (!fs::exists(filePath, ec)) {
            if (ec) {
                return Error("Error checking file existence: " + ec.message());
            }
            return Error();  // 文件不存在也视为成功
        }
        
        // 删除文件
        if (!fs::remove(filePath, ec)) {
            if (ec) {
                return Error("Failed to remove file: " + ec.message());
            }
        }
        return Error();
    } catch (const std::exception& e) {
        return Error("Failed to remove metadata: " + std::string(e.what()));
    }
}

std::vector<std::string> MetadataStore::List(const std::string& gun) {
    std::vector<std::string> result;
    std::string gunDir = trustDir_ + "/" + gun;
    
    try {
        // 检查目录是否存在
        std::error_code ec;
        if (!fs::exists(gunDir, ec)) {
            if (ec) {
                // 记录错误但返回空列表
                return result;
            }
            return result;
        }
        
        // 遍历目录
        for (const auto& entry : fs::directory_iterator(gunDir, ec)) {
            if (ec) {
                // 记录错误但继续遍历
                continue;
            }
            if (entry.is_regular_file(ec) && entry.path().extension() == ".json") {
                // 获取文件名（不包含扩展名）
                std::string filename = entry.path().stem().string();
                result.push_back(filename);
            }
        }
    } catch (const std::exception&) {
        // 忽略错误，返回空列表
    }
    
    return result;
}

std::string MetadataStore::getMetadataPath(const std::string& gun,
                                          const std::string& role) const {
    return trustDir_ + "/" + gun + "/" + role + ".json";
}

RemoteStore::RemoteStore(const std::string& serverURL)
    : serverURL_(serverURL) {
}

Result<json> RemoteStore::GetRemote(const std::string& gun,
                                  const std::string& role) {
    // TODO: 实现 HTTP 请求获取远程元数据
    return Result<json>(Error("Not implemented"));
}

Error RemoteStore::SetRemote(const std::string& gun,
                           const std::string& role,
                           const json& data) {
    // TODO: 实现 HTTP 请求设置远程元数据
    return Error("Not implemented");
}

} // namespace storage
} // namespace notary 