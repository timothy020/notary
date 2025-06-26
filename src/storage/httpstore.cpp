#include "notary/storage/httpstore.hpp"
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <system_error>
#include <curl/curl.h>
#include <sstream>
#include <iostream>
#include "notary/utils/logger.hpp"

namespace notary {
namespace storage {

namespace fs = std::filesystem;

// libcurl写入回调函数
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
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

// 构造函数 - 对应Go版本的NewHTTPStore
HttpStore::HttpStore(const std::string& baseURL, 
                       const std::string& metaPrefix,
                       const std::string& metaExtension,
                       const std::string& keyExtension)
    : baseURL_(baseURL)
    , metaPrefix_(metaPrefix)
    , metaExtension_(metaExtension)
    , keyExtension_(keyExtension) {
    // 全局初始化libcurl (应当在程序入口处只初始化一次)
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

// 辅助工厂方法 - 对应Go版本的NewNotaryServerStore
std::unique_ptr<HttpStore> HttpStore::NewNotaryServerStore(const std::string& serverURL, const std::string& gun) {
    // 构建完整的baseURL，包含gun路径 - 对应Go版本的serverURL+"/v2/"+gun.String()+"/_trust/tuf/"
    std::string fullBaseURL = serverURL + "/v2/" + gun + "/_trust/tuf/";
    
    return std::make_unique<HttpStore>(
        fullBaseURL,
        "",      // metaPrefix为空字符串
        "json",  // metaExtension
        "key"    // keyExtension
    );
}

// URL构建辅助方法 - 对应Go版本的buildMetaURL
std::string HttpStore::buildMetaURL(const std::string& name) const {
    std::string filename;
    if (!name.empty()) {
        filename = name + "." + metaExtension_;
    }
    
    // 对应Go版本的path.Join(s.metaPrefix, filename)
    std::string uri;
    if (!metaPrefix_.empty()) {
        uri = metaPrefix_;
        if (!filename.empty()) {
            if (uri.back() != '/') uri += "/";
            uri += filename;
        }
    } else {
        uri = filename;
    }
    
    return buildURL(uri);
}

// URL构建辅助方法 - 对应Go版本的buildKeyURL
std::string HttpStore::buildKeyURL(const std::string& name) const {
    std::string filename = name + "." + keyExtension_;
    
    // 对应Go版本的path.Join(s.metaPrefix, filename)
    std::string uri;
    if (!metaPrefix_.empty()) {
        uri = metaPrefix_;
        if (uri.back() != '/') uri += "/";
        uri += filename;
    } else {
        uri = filename;
    }
    
    return buildURL(uri);
}

// URL构建辅助方法 - 对应Go版本的buildURL
std::string HttpStore::buildURL(const std::string& uri) const {
    // 简单的URL连接，对应Go版本的baseURL.ResolveReference(sub)
    std::string result = baseURL_;
    if (!uri.empty()) {
        if (!result.empty() && result.back() != '/') {
            result += "/";
        }
        result += uri;
    }
    utils::GetLogger().Info("URL: " + result);
    return result;
}

// 实现Get方法 - 调用GetSized的默认版本
Result<std::vector<uint8_t>> HttpStore::Get(const std::string& name) {
    return GetSized(name, NO_SIZE_LIMIT);
}

// GetSized - 对应Go版本的GetSized方法
Result<std::vector<uint8_t>> HttpStore::GetSized(const std::string& name, int64_t size) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize CURL"));
    }
    
    // 构建URL - 使用buildMetaURL
    // 例："http://localhost:4443/v2/docker.io/library/myapp/_trust/tuf/root.json"
    std::string url = buildMetaURL(name);
    
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
        return Result<std::vector<uint8_t>>(Error("CURL request failed: " + errorMsg));
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    double contentLength = 0;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &contentLength);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码
    Error httpError = translateStatusToError(httpCode, name);
    if (!httpError.ok()) {
        return Result<std::vector<uint8_t>>(httpError);
    }

    // 处理大小限制 - 对应Go版本的逻辑
    int64_t actualSize = size;
    if (size == NO_SIZE_LIMIT) {
        actualSize = MAX_DOWNLOAD_SIZE;
    }
    
    // 检查Content-Length是否超过限制 - 对应Go版本的ErrMaliciousServer
    if (contentLength > 0 && static_cast<int64_t>(contentLength) > actualSize) {
        return Result<std::vector<uint8_t>>(Error("Content-Length exceeds size limit - potential malicious server"));
    }
    
    // 限制实际读取的数据量 - 对应Go版本的io.LimitReader
    size_t maxRead = static_cast<size_t>(actualSize);
    if (responseBuffer.size() > maxRead) {
        responseBuffer.resize(maxRead);
    }
    
    // 验证响应是否为有效JSON格式，并转换为uint8_t vector
    try {
        // 解析JSON以验证格式正确性
        json responseJson = json::parse(responseBuffer);
        
        // 重新序列化以确保格式一致性
        std::string formattedJsonStr = responseJson.dump();
        std::vector<uint8_t> result(formattedJsonStr.begin(), formattedJsonStr.end());
        return Result<std::vector<uint8_t>>(std::move(result));
        
    } catch (const json::exception& e) {
        return Result<std::vector<uint8_t>>(Error("Failed to parse JSON metadata response: " + std::string(e.what())));
    }
}

// GetKey - 对应Go版本的GetKey方法
Result<std::vector<uint8_t>> HttpStore::GetKey(const std::string& name) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize CURL"));
    }
    
    // 构建URL - 使用buildKeyURL
    // 例："http://localhost:4443/v2/docker.io/library/myapp/_trust/tuf/timestamp.key"
    std::string url = buildKeyURL(name);
    
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
        return Result<std::vector<uint8_t>>(Error("CURL request failed: " + errorMsg));
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);    
    curl_easy_cleanup(curl);

    // 处理HTTP状态码
    Error httpError = translateStatusToError(httpCode, name + " key");
    if (!httpError.ok()) {
        return Result<std::vector<uint8_t>>(httpError);
    }
    
    // 解析JSON响应
    try {
        // 响应格式应该是: {"keytype":"ecdsa","keyval":{"public":"BASE64_DATA","private":null}}
        json keyJson = json::parse(responseBuffer);
        
        // 验证响应格式
        if (!keyJson.contains("keyval") || !keyJson["keyval"].contains("public")) {
            return Result<std::vector<uint8_t>>(Error("Invalid key response format"));
        }
        
        // 将完整的JSON响应转换为字节数组返回
        std::string keyJsonStr = keyJson.dump();
        std::vector<uint8_t> result(keyJsonStr.begin(), keyJsonStr.end());
        return Result<std::vector<uint8_t>>(std::move(result));
        
    } catch (const json::exception& e) {
        return Result<std::vector<uint8_t>>(Error("Failed to parse JSON key response: " + std::string(e.what())));
    }
}

// Set - 对应Go版本的Set方法
Error HttpStore::Set(const std::string& name, const std::vector<uint8_t>& data) {
    // 将单个元数据包装成map，复用SetMulti的逻辑
    std::map<std::string, std::vector<uint8_t>> singleMeta;
    singleMeta[name] = data;
    
    return SetMulti(singleMeta);
}

// SetMulti - 对应Go版本的SetMulti方法
Error HttpStore::SetMulti(const std::map<std::string, std::vector<uint8_t>>& metas) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Error("Failed to initialize CURL");
    }
    
    // 构建URL - 对应Go版本的buildMetaURL("")
    // 例："http://localhost:4443/v2/docker.io/library/myapp/_trust/tuf/"
    std::string url = buildMetaURL("");
    
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
        
        // 设置内容类型为JSON，因为data虽然是vector<uint8_t>，但内容是JSON格式
        curl_mime_type(part, "application/json");
        
        // 设置数据 - data是JSON的字节表示，直接发送
        curl_mime_data(part, reinterpret_cast<const char*>(data.data()), data.size());
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

// Remove - 对应Go版本的Remove方法
// 总是失败，因为我们永远不应该能够远程删除单个元数据文件
Error HttpStore::Remove(const std::string& name) {
    return Error("cannot delete individual metadata files");
}

// RemoveAll - 对应Go版本的RemoveAll方法
Error HttpStore::RemoveAll() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Error("Failed to initialize CURL");
    }
    
    // 构建URL，空的元数据路径表示删除所有 - 对应Go版本的buildMetaURL("")
    std::string url = buildMetaURL("");
    
    // 设置CURL选项为DELETE请求 - 对应Go版本的http.NewRequest("DELETE", url.String(), nil)
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");  // 设置DELETE方法
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    
    // 接收响应数据的字符串
    std::string responseBuffer;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    
    // 执行请求 - 对应Go版本的s.roundTrip.RoundTrip(req)
    CURLcode res = curl_easy_perform(curl);
    
    // 检查请求是否成功
    if (res != CURLE_OK) {
        std::string errorMsg = curl_easy_strerror(res);
        curl_easy_cleanup(curl);
        return Error("CURL DELETE request failed: " + errorMsg);
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);
    
    // 处理HTTP状态码 - 对应Go版本的translateStatusToError
    return translateStatusToError(httpCode, "DELETE metadata for GUN endpoint");
}

// RotateKey - 对应Go版本的rotateKey方法
// 请求服务器轮转指定角色的密钥
Result<std::vector<uint8_t>> HttpStore::RotateKey(const std::string& role) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return Result<std::vector<uint8_t>>(Error("Failed to initialize CURL"));
    }
    
    // 构建轮转密钥的URL - 类似于buildKeyURL但是用于轮转
    // 例："http://localhost:4443/v2/docker.io/library/myapp/_trust/tuf/timestamp.key/rotate"
    std::string url = buildKeyURL(role) + "/rotate";
    
    // 设置CURL选项为POST请求来请求密钥轮转
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L); // 设置为POST请求
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 启用SSL验证
    
    // 设置空的POST数据（只需要POST请求即可触发轮转）
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    
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
        return Result<std::vector<uint8_t>>(Error("CURL key rotation request failed: " + errorMsg));
    }
    
    // 获取HTTP状态码
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);    
    curl_easy_cleanup(curl);

    // 处理HTTP状态码
    Error httpError = translateStatusToError(httpCode, role + " key rotation");
    if (!httpError.ok()) {
        return Result<std::vector<uint8_t>>(httpError);
    }
    
    // 验证响应是否为有效JSON格式，并转换为uint8_t vector
    try {
        // 解析JSON以验证格式正确性
        json responseJson = json::parse(responseBuffer);
        
        // 验证响应格式 - 应该包含新的密钥信息
        if (!responseJson.contains("keyval") || !responseJson["keyval"].contains("public")) {
            return Result<std::vector<uint8_t>>(Error("Invalid key rotation response format"));
        }
        
        // 重新序列化以确保格式一致性
        std::string formattedJsonStr = responseJson.dump();
        std::vector<uint8_t> result(formattedJsonStr.begin(), formattedJsonStr.end());
        return Result<std::vector<uint8_t>>(std::move(result));
        
    } catch (const json::exception& e) {
        return Result<std::vector<uint8_t>>(Error("Failed to parse JSON key rotation response: " + std::string(e.what())));
    }
}

// ListFiles - HttpStore不支持列出文件，返回空列表
std::vector<std::string> HttpStore::ListFiles() {
    // HTTP存储不支持列出文件操作
    return {};
}

// Location - 对应Go版本的Location方法
std::string HttpStore::Location() const {
    // 从baseURL_中提取主机名，完全等价于Go版本的url.URL.Host
    // 例如: "https://user:pass@notary.docker.io:443/path" -> "notary.docker.io:443"
    
    std::string url = baseURL_;
    
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