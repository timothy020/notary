#include "notary/storage/metadata_store.hpp"
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <system_error>
#include <curl/curl.h>
#include <sstream>
#include <iostream>

namespace notary {
namespace storage {

namespace fs = std::filesystem;

// libcurl写入回调函数
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

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

RemoteStore::RemoteStore(const std::string& serverURL, 
                       const std::string& metaExtension,
                       const std::string& keyExtension)
    : serverURL_(serverURL)
    , metaExtension_(metaExtension)
    , keyExtension_(keyExtension) {
    // 全局初始化libcurl (应当在程序入口处只初始化一次)
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

// 处理HTTP状态码，将其转换为适当的错误
Error translateStatusToError(long statusCode, const std::string& resource) {
    switch (statusCode) {
        case 200: // OK
            return Error();
        case 404: // Not Found
            return Error("Metadata not found: " + resource);
        case 400: // Bad Request
            return Error("Invalid operation");
        default:
            return Error("Server unavailable with code: " + std::to_string(statusCode));
    }
}

Result<json> RemoteStore::GetRemote(const std::string& gun, const std::string& role) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Result<json>(Error("Failed to initialize CURL"));
    }
    
    // 构建URL - 使用metaExtension_扩展名
    // 例："http://localhost:4443/v2/docker.io/library/myapp/_trust/tuf/root.json"
    std::string url = serverURL_ + "/v2/" + gun + "/_trust/tuf/" + role + "." + metaExtension_;
    
    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    
    // 接收数据的字符串
    std::string responseBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    
    // 执行请求
    CURLcode res = curl_easy_perform(curl);
    
    // 检查请求是否成功
    if (res != CURLE_OK) {
        std::string errorMsg = curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        return Result<json>(Error("CURL request failed: " + errorMsg));
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码
    Error httpError = translateStatusToError(httpCode, role);
    if (!httpError.ok()) {
        return Result<json>(httpError);
    }
    
    // 解析JSON响应
    try {
        json responseJson = json::parse(responseBuffer);
        return Result<json>(responseJson);
    } catch (const json::exception& e) {
        return Result<json>(Error("Failed to parse JSON response: " + std::string(e.what())));
    }
}

Result<json> RemoteStore::GetKey(const std::string& gun, const std::string& role) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Result<json>(Error("Failed to initialize CURL"));
    }
    
    // 构建URL - 注意这里使用keyExtension_而不是metaExtension_
    std::string url = serverURL_ + "/v2/" + gun + "/_trust/tuf/" + role + "." + keyExtension_;
    
    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    
    // 接收数据的字符串
    std::string responseBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    
    // 执行请求
    CURLcode res = curl_easy_perform(curl);
    
    // 检查请求是否成功
    if (res != CURLE_OK) {
        std::string errorMsg = curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        return Result<json>(Error("CURL request failed: " + errorMsg));
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码
    Error httpError = translateStatusToError(httpCode, role + " key");
    if (!httpError.ok()) {
        return Result<json>(httpError);
    }
    
    // 解析JSON响应
    try {
        // 响应格式应该是: {"keytype":"ecdsa","keyval":{"public":"BASE64_DATA","private":null}}
        json keyJson = json::parse(responseBuffer);
        return Result<json>(keyJson);
    } catch (const json::exception& e) {
        return Result<json>(Error("Failed to parse JSON key response: " + std::string(e.what())));
    }
}

// 用于multipart/form-data上传的辅助函数
struct UploadData {
    std::string data;
    size_t pos = 0;
};

// 读取回调函数，用于上传数据
static size_t ReadCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    UploadData* uploadData = static_cast<UploadData*>(userdata);
    size_t buffer_size = size * nitems;
    
    if (uploadData->pos >= uploadData->data.size()) {
        return 0; // 数据已全部读取
    }
    
    // 计算剩余要读取的数据量
    size_t to_copy = std::min(buffer_size, uploadData->data.size() - uploadData->pos);
    memcpy(buffer, uploadData->data.c_str() + uploadData->pos, to_copy);
    uploadData->pos += to_copy;
    
    return to_copy;
}

Error RemoteStore::SetRemote(const std::string& gun, const std::string& role, const json& data) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Error("Failed to initialize CURL");
    }
    
    // 构建URL - 使用metaExtension_扩展名
    std::string url = serverURL_ + "/v2/" + gun + "/_trust/tuf/";
    
    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    curl_easy_setopt(curl, CURLOPT_POST, 1L); // 设置为POST请求
    
    // 准备multipart/form-data
    struct curl_mime* mime = curl_mime_init(curl);
    struct curl_mimepart* part = curl_mime_addpart(mime);
    
    // 设置文件名和表单字段名
    curl_mime_name(part, "files");
    curl_mime_filename(part, (role + "." + metaExtension_).c_str());
    
    // 设置内容类型
    curl_mime_type(part, "application/json");
    
    // 设置数据
    std::string dataStr = data.dump();
    curl_mime_data(part, dataStr.c_str(), dataStr.size());
    
    // 设置multipart表单
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    
    // 响应缓冲区
    std::string responseBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    
    // 执行请求
    CURLcode res = curl_easy_perform(curl);
    
    // 清理mime资源
    curl_mime_free(mime);
    
    // 检查请求是否成功
    if (res != CURLE_OK) {
        std::string errorMsg = curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        return Error("CURL request failed: " + errorMsg);
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码
    return translateStatusToError(httpCode, "POST metadata");
}

} // namespace storage
} // namespace notary 