#pragma once

#include <string>
#include <functional>
#include <memory>
#include <vector>
#include <map>
#include <chrono>
#include "notary/crypto/crypto_service.hpp"
#include "notary/server/errors.hpp"
#include "notary/types.hpp"
#include <nlohmann/json.hpp>

// 前向声明
namespace httplib {
    class Request;
    class Response;
}

namespace notary {
namespace server {

using json = nlohmann::json;

// 元数据结构
struct Metadata {
    std::string data;       // 元数据JSON内容
    std::string checksum;   // 元数据校验和
    int version;            // 元数据版本
    std::chrono::system_clock::time_point timestamp; // 最后修改时间
};

// 元数据请求结构
struct MetadataRequest {
    std::string gun;        // GUN名称
    std::string role;          // 角色
    std::string roleName;   // 原始角色名（用于delegation处理）
    std::string checksum;   // 校验和（可选）
    int version = 0;        // 版本号（可选，0表示最新）
};

// 存储服务接口
class StorageService {
public:
    virtual ~StorageService() = default;
    
    // 获取元数据
    virtual Result<Metadata> GetMetadata(const MetadataRequest& request) = 0;
    
    // 存储元数据
    virtual Result<bool> StoreMetadata(const std::string& gun, const std::string& role, 
                               const std::string& roleName, const std::string& data) = 0;
    
    // 删除GUN相关的所有元数据
    virtual Result<bool> DeleteGUN(const std::string& gun) = 0;
};

// 请求和响应结构
struct Request {
    // 文件上传结构
    struct File {
        std::string field_name;  // 添加字段名
        std::string filename;
        std::string content_type;
        std::string content;
    };
    
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
    std::map<std::string, std::string> params; // 路径参数
    std::vector<File> files; // 改为vector以支持多个同名字段
};

struct Response {
    int status;
    std::map<std::string, std::string> headers;
    std::string body;
};

// 上下文
struct Context {
    Request request;
    crypto::CryptoService* cryptoService;
    std::string keyAlgorithm;
    StorageService* storageService; // 存储服务
    // 其他可能需要的上下文信息
};

// 处理器函数类型
using Handler = std::function<Error(const Context&, Response&)>;

// 路由器
class Router {
public:
    void AddRoute(const std::string& method, const std::string& path, Handler handler);
    Error HandleRequest(const Context& ctx, Response& response);

private:
    struct Route {
        std::string method;
        std::string path;
        Handler handler;
    };
    std::vector<Route> routes_;
    
    // 匹配路由并提取参数
    bool matchRoute(const std::string& path, const std::string& routePath, 
                   std::map<std::string, std::string>& params);
};

// 日志配置
struct LoggingConfig {
    std::string level = "info";     // 日志级别: debug, info, warn, error, fatal, panic
    std::string format = "json";    // 日志格式: json, text
    std::string output = "console"; // 日志输出: console, file
    std::string file = "notary-server.log"; // 日志文件路径(当output为file时使用)
};

// 服务器配置
struct Config {
    std::string addr;
    crypto::CryptoService* cryptoService;
    std::string keyAlgorithm;
    std::vector<std::string> repoPrefixes;
    LoggingConfig logging;  // 日志配置
    StorageService* storageService; // 存储服务
};

// 服务器
class Server {
public:
    explicit Server(const Config& config);
    Error Run();
    
private:
    void setupRoutes();
    void setupLogger();
    void handleHttpRequest(const std::string& method, const httplib::Request& req, httplib::Response& res);
    
    Config config_;
    Router router_;
};

// 处理函数声明
namespace handlers {
    Error MainHandler(const Context& ctx, Response& resp);
    Error GetKeyHandler(const Context& ctx, Response& resp);
    Error RotateKeyHandler(const Context& ctx, Response& resp);
    Error NotFoundHandler(const Context& ctx, Response& resp);
    Error AtomicUpdateHandler(const Context& ctx, Response& resp);
    Error GetHandler(const Context& ctx, Response& resp);
    Error DeleteHandler(const Context& ctx, Response& resp);
}

} // namespace server
} // namespace notary 