#include "notary/server/server.hpp"
#include <iostream>
#include <regex>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "notary/types.hpp"

namespace notary {
namespace server {

void Router::AddRoute(const std::string& method, const std::string& path, Handler handler) {
    routes_.push_back({method, path, handler});
}

bool Router::matchRoute(const std::string& path, const std::string& routePath, 
                       std::map<std::string, std::string>& params) {
    // 将路由路径转换为正则表达式
    std::string pattern = routePath;
    
    // 替换 {gun:[^*]+} 这样的模式为捕获组
    std::regex paramRegex("\\{([a-zA-Z0-9]+):(.*?)\\}");
    std::string regexPattern;
    
    std::smatch matches;
    std::string::const_iterator searchStart(pattern.cbegin());
    
    std::vector<std::string> paramNames;
    
    while (std::regex_search(searchStart, pattern.cend(), matches, paramRegex)) {
        regexPattern += std::string(searchStart, searchStart + matches.position());
        regexPattern += "(" + std::string(matches[2]) + ")";
        
        paramNames.push_back(matches[1]);
        
        searchStart += matches.position() + matches.length();
    }
    
    regexPattern += std::string(searchStart, pattern.cend());
    
    // 添加开始和结束标记
    regexPattern = "^" + regexPattern + "$";
    
    std::regex fullRegex(regexPattern);
    std::smatch pathMatches;
    
    if (std::regex_match(path, pathMatches, fullRegex)) {
        // 将捕获组匹配结果填入参数表
        for (size_t i = 0; i < paramNames.size(); ++i) {
            // pathMatches[0]是整个匹配，从1开始是捕获组
            params[paramNames[i]] = pathMatches[i + 1].str();
        }
        return true;
    }
    
    return false;
}

Error Router::HandleRequest(const Context& ctx, Response& response) {
    for (const auto& route : routes_) {
        if (route.method == ctx.request.method) {
            std::map<std::string, std::string> params;
            if (matchRoute(ctx.request.path, route.path, params)) {
                // 创建新的上下文，包含解析的参数
                Context newCtx = ctx;
                newCtx.request.params = params;
                
                // 调用处理函数
                return route.handler(newCtx, response);
            }
        }
    }
    
    // 没有匹配的路由，返回404
    return handlers::NotFoundHandler(ctx, response);
}

Server::Server(const Config& config) : config_(config) {
    setupRoutes();
}

void Server::setupRoutes() {
    // 添加路由
    router_.AddRoute("GET", "/v2/", handlers::MainHandler);
    
    // 处理密钥获取请求 - 修改gun匹配模式以支持多段路径
    router_.AddRoute("GET", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/{tufRole:snapshot|timestamp}.key", handlers::GetKeyHandler);
    
    // 处理密钥轮换请求
    router_.AddRoute("POST", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/{tufRole:snapshot|timestamp}.key", handlers::RotateKeyHandler);
    
    // 处理元数据更新请求
    router_.AddRoute("POST", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/", handlers::AtomicUpdateHandler);
    
    // 处理元数据获取请求
    router_.AddRoute("GET", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.{checksum:[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}}.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/{version:[1-9]*[0-9]+}.{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/{tufRole:root|targets(?:/[^/\\s]+)*|snapshot|timestamp}.json", handlers::GetHandler);
    
    // 处理元数据删除请求
    router_.AddRoute("DELETE", "/v2/{gun:[^/]+(?:/[^/]+)*}/_trust/tuf/", handlers::DeleteHandler);
}

Error Server::Run() {
    std::cout << "启动notary服务器，监听地址: " << config_.addr << std::endl;
    
    // 解析地址和端口
    std::string host;
    int port;
    
    size_t colonPos = config_.addr.find(':');
    if (colonPos != std::string::npos) {
        host = config_.addr.substr(0, colonPos);
        port = std::stoi(config_.addr.substr(colonPos + 1));
    } else {
        host = "0.0.0.0";
        port = std::stoi(config_.addr);
    }
    
    httplib::Server server;
    
    // 设置通用处理器
    server.set_base_dir("./"); // 设置静态文件目录
    
    // 用通用处理程序处理所有请求
    server.set_default_headers({{"Server", "Notary/1.0"}});
    
    server.set_exception_handler([](const auto& req, auto& res, std::exception_ptr ep) {
        try {
            std::rethrow_exception(ep);
        } catch (std::exception& e) {
            res.status = 500;
            res.set_content("{\"errors\":[{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"" + 
                            std::string(e.what()) + "\"}]}", "application/json");
        } catch (...) {
            res.status = 500;
            res.set_content("{\"errors\":[{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Unknown error\"}]}", 
                            "application/json");
        }
    });
    
    // 通用处理器
    server.set_mount_point("/", "./");
    
    // 创建全局处理程序
    server.set_logger([](const auto& req, const auto& res) {
        std::cout << req.method << " " << req.path << " - " << res.status << std::endl;
    });
    
    // 添加所有路由
    server.Get(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handleHttpRequest("GET", req, res);
    });
    
    server.Post(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handleHttpRequest("POST", req, res);
    });
    
    server.Delete(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handleHttpRequest("DELETE", req, res);
    });
    
    // 启动服务器
    if (!server.listen(host.c_str(), port)) {
        return Error(1, "无法启动服务器"); // ErrUnknown
    }
    
    return Error();
}

void Server::handleHttpRequest(const std::string& method, const httplib::Request& req, httplib::Response& res) {
    // 创建请求上下文
    Request request;
    request.method = method;
    request.path = req.path;
    request.body = req.body;
    
    // 转换headers
    for (const auto& header : req.headers) {
        request.headers[header.first] = header.second;
    }
    
    // 创建上下文
    Context ctx;
    ctx.request = request;
    ctx.cryptoService = config_.cryptoService;
    ctx.keyAlgorithm = config_.keyAlgorithm;
    
    // 创建响应对象
    Response response;
    response.status = 200;
    
    // 处理请求
    Error err = router_.HandleRequest(ctx, response);
    
    // 设置响应状态码
    if (err.Code() != 0) { // 0 = NoError
        response.status = err.HTTPStatusCode();
        
        // 如果有错误，设置JSON格式的错误信息
        json errorJson = {
            {"errors", {
                {
                    {"code", err.Code()},
                    {"message", err.Detail()}
                }
            }}
        };
        
        response.body = errorJson.dump();
        response.headers["Content-Type"] = "application/json";
    }
    
    // 设置响应头
    for (const auto& header : response.headers) {
        res.set_header(header.first.c_str(), header.second.c_str());
    }
    
    // 设置响应体和状态码
    res.status = response.status;
    res.set_content(response.body, "application/json");
}

} // namespace server
} // namespace notary 