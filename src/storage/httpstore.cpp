#include "notary/storage/httpstore.hpp"
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

Result<json> RemoteStore::GetSized(const std::string& gun, const std::string& role, int64_t size) {
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

    double contentLength = 0;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &contentLength);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码
    Error httpError = translateStatusToError(httpCode, role);
    if (!httpError.ok()) {
        return Result<json>(httpError);
    }

    // 处理大小限制 - 对应Go版本的逻辑
    int64_t actualSize = size;
    if (size == NO_SIZE_LIMIT) {
        actualSize = MAX_DOWNLOAD_SIZE;
    }
    
    // 检查Content-Length是否超过限制 - 对应Go版本的ErrMaliciousServer
    if (contentLength > 0 && static_cast<int64_t>(contentLength) > actualSize) {
        return Result<json>(Error("Content-Length exceeds size limit - potential malicious server"));
    }
    
    // 限制实际读取的数据量 - 对应Go版本的io.LimitReader
    size_t maxRead = static_cast<size_t>(actualSize);
    if (responseBuffer.size() > maxRead) {
        responseBuffer.resize(maxRead);
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

Error RemoteStore::Set(const std::string& gun, const std::string& role, const json& data) {
    // 将单个元数据包装成map，复用SetMulti的逻辑
    std::map<std::string, json> singleMeta;
    singleMeta[role] = data;
    
    return SetMulti(gun, singleMeta);
}

// 批量发布多个元数据到远程 - 对应Go版本的SetMulti
Error RemoteStore::SetMulti(const std::string& gun, const std::map<std::string, json>& metas) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Error("Failed to initialize CURL");
    }
    
    // 构建URL - 对应Go版本的buildMetaURL("")
    std::string url = serverURL_ + "/v2/" + gun + "/_trust/tuf/";
    
    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    curl_easy_setopt(curl, CURLOPT_POST, 1L); // 设置为POST请求
    
    // 准备multipart/form-data - 对应Go版本的NewMultiPartMetaRequest
    struct curl_mime* mime = curl_mime_init(curl);
    
    // 为每个元数据文件添加一个part
    for (const auto& [role, data] : metas) {
        struct curl_mimepart* part = curl_mime_addpart(mime);
        
        // 设置文件名和表单字段名 - 对应Go版本的CreateFormFile("files", role)
        curl_mime_name(part, "files");
        curl_mime_filename(part, role.c_str()); // 文件名直接是角色名，不加扩展名
        
        // 设置内容类型
        curl_mime_type(part, "application/json");
        
        // 设置数据
        std::string dataStr = data.dump();
        curl_mime_data(part, dataStr.c_str(), dataStr.size());
    }
    
    // 设置multipart表单
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    
    // 响应缓冲区
    std::string responseBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    
    // 执行请求 - 对应Go版本的roundTrip.RoundTrip(req)
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
    
    // 处理HTTP状态码 - 对应Go版本的translateStatusToError(resp, "POST metadata endpoint")
    return translateStatusToError(httpCode, "POST metadata endpoint");
}

// 删除单个元数据文件 - 对应Go版本的Remove方法
// 总是失败，因为我们永远不应该能够远程删除单个元数据文件
Error RemoteStore::Remove(const std::string& name) {
    return Error("cannot delete individual metadata files");
}

// 删除GUN的所有远程元数据 (对应Go版本的RemoveAll)
Result<bool> RemoteStore::RemoveAll() const {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Result<bool>(Error("Failed to initialize CURL"));
    }
    
    // 构建URL，空的元数据路径表示删除所有 (对应Go的buildMetaURL(""))
    std::string url = serverURL_;
    
    // 设置CURL选项为DELETE请求 (对应Go的http.NewRequest("DELETE", url.String(), nil))
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");  // 设置DELETE方法
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    
    // 接收响应数据的字符串
    std::string responseBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    
    // 执行请求 (对应Go的s.roundTrip.RoundTrip(req))
    CURLcode res = curl_easy_perform(curl);
    
    // 检查请求是否成功
    if (res != CURLE_OK) {
        std::string errorMsg = curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        return Result<bool>(Error("CURL DELETE request failed: " + errorMsg));
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码 (对应Go的translateStatusToError)
    Error httpError = translateStatusToError(httpCode, "DELETE metadata for GUN endpoint");
    if (!httpError.ok()) {
        return Result<bool>(httpError);
    }
    
    // 删除成功
    return Result<bool>(true);
}

// 返回存储位置的可读名称 - 对应Go版本的Location
std::string RemoteStore::Location() const {
    // 从serverURL_中提取主机名，完全等价于Go版本的url.URL.Host
    // 例如: "https://user:pass@notary.docker.io:443/path" -> "notary.docker.io:443"
    
    std::string url = serverURL_;
    
    // 移除协议前缀 (http:// 或 https://)
    size_t protocolPos = url.find("://");
    if (protocolPos != std::string::npos) {
        url = url.substr(protocolPos + 3);
    }
    
    // 移除用户认证信息 (user:pass@)
    size_t atPos = url.find('@');
    if (atPos != std::string::npos) {
        url = url.substr(atPos + 1);
    }
    
    // 查找路径分隔符，只保留主机部分
    size_t pathPos = url.find('/');
    if (pathPos != std::string::npos) {
        url = url.substr(0, pathPos);
    }
    
    // 移除查询参数和片段
    size_t queryPos = url.find('?');
    if (queryPos != std::string::npos) {
        url = url.substr(0, queryPos);
    }
    
    size_t fragmentPos = url.find('#');
    if (fragmentPos != std::string::npos) {
        url = url.substr(0, fragmentPos);
    }
    
    // 现在url只包含主机名和端口号，完全等价于Go的url.URL.Host
    return url;
}

} // namespace storage
} // namespace notary 