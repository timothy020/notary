#pragma once

#include <string>
#include <functional>
#include <memory>
#include <vector>
#include <map>
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

// 请求和响应结构
struct Request {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
    std::map<std::string, std::string> params; // 路径参数
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

// 服务器配置
struct Config {
    std::string addr;
    crypto::CryptoService* cryptoService;
    std::string keyAlgorithm;
    std::vector<std::string> repoPrefixes;
};

// 服务器
class Server {
public:
    explicit Server(const Config& config);
    Error Run();
    
private:
    void setupRoutes();
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