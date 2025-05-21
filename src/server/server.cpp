#include "notary/server/server.hpp"
#include <iostream>
#include <regex>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "notary/types.hpp"
#include "notary/utils/logger.hpp"

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
                
                // 记录路由匹配信息
                utils::GetLogger().Debug("匹配到路由", 
                    utils::LogContext()
                        .With("method", route.method)
                        .With("path", route.path)
                        .With("requestPath", ctx.request.path));
                
                // 调用处理函数
                return route.handler(newCtx, response);
            }
        }
    }
    
    // 记录未找到路由的信息
    utils::GetLogger().Warn("未找到匹配的路由", 
        utils::LogContext()
            .With("method", ctx.request.method)
            .With("path", ctx.request.path));
    
    // 没有匹配的路由，返回404
    return handlers::NotFoundHandler(ctx, response);
}

Server::Server(const Config& config) : config_(config) {
    setupLogger();
    setupRoutes();
}

void Server::setupLogger() {
    // 初始化日志系统
    utils::GetLogger().Initialize(
        config_.logging.level,
        config_.logging.format,
        config_.logging.output
    );
    
    // 记录初始化信息
    utils::GetLogger().Info("初始化notary服务器", 
        utils::LogContext()
            .With("address", config_.addr)
            .With("logLevel", config_.logging.level)
            .With("logFormat", config_.logging.format));
}

void Server::setupRoutes() {
    // 添加路由
    router_.AddRoute("GET", "/v2/", handlers::MainHandler);
    
    // 处理密钥获取请求 - 简化匹配模式
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/{tufRole:snapshot|timestamp}.key", handlers::GetKeyHandler);
    
    // 处理密钥轮换请求
    router_.AddRoute("POST", "/v2/{gun:.+}/_trust/tuf/{tufRole:snapshot|timestamp}.key", handlers::RotateKeyHandler);
    
    // 处理元数据更新请求
    router_.AddRoute("POST", "/v2/{gun:.+}/_trust/tuf/", handlers::AtomicUpdateHandler);
    
    // 处理元数据获取请求 - 大幅简化正则表达式
    // 基本角色的标准形式
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/root.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/targets.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/snapshot.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/timestamp.json", handlers::GetHandler);
    
    // 带版本号的形式
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/{version:[0-9]+}.root.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/{version:[0-9]+}.targets.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/{version:[0-9]+}.snapshot.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/{version:[0-9]+}.timestamp.json", handlers::GetHandler);
    
    // 带校验和的形式 - 使用通配形式避免复杂正则表达式
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/root.{checksum:[a-fA-F0-9]+}.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/targets.{checksum:[a-fA-F0-9]+}.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/snapshot.{checksum:[a-fA-F0-9]+}.json", handlers::GetHandler);
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/timestamp.{checksum:[a-fA-F0-9]+}.json", handlers::GetHandler);
    
    // 处理委托目标（delegated targets）
    router_.AddRoute("GET", "/v2/{gun:.+}/_trust/tuf/targets/{delegatedRole:.+}.json", handlers::GetHandler);
    
    // 处理元数据删除请求
    router_.AddRoute("DELETE", "/v2/{gun:.+}/_trust/tuf/", handlers::DeleteHandler);
    
    utils::GetLogger().Debug("路由设置完成");
}

Error Server::Run() {
    utils::GetLogger().Info("启动notary服务器", 
        utils::LogContext().With("address", config_.addr));
    
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
            // 记录异常
            utils::GetLogger().Error("服务器异常", 
                utils::LogContext()
                    .With("exception", e.what())
                    .With("path", req.path)
                    .With("method", req.method));
            
            res.status = 500;
            res.set_content("{\"errors\":[{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"" + 
                            std::string(e.what()) + "\"}]}", "application/json");
        } catch (...) {
            utils::GetLogger().Error("服务器未知异常", 
                utils::LogContext()
                    .With("path", req.path)
                    .With("method", req.method));
            
            res.status = 500;
            res.set_content("{\"errors\":[{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Unknown error\"}]}", 
                            "application/json");
        }
    });
    
    // 通用处理器
    server.set_mount_point("/", "./");
    
    // 创建全局处理程序
    server.set_logger([](const auto& req, const auto& res) {
        utils::LogContext ctx;
        ctx.WithField("method", req.method);
        ctx.WithField("path", req.path);
        ctx.WithField("status", std::to_string(res.status));
        ctx.WithField("remoteAddr", req.remote_addr);
        
        // 根据状态码选择日志级别
        if (res.status >= 500) {
            utils::GetLogger().Error("HTTP请求完成", ctx);
        } else if (res.status >= 400) {
            utils::GetLogger().Warn("HTTP请求完成", ctx);
        } else {
            utils::GetLogger().Info("HTTP请求完成", ctx);
        }
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
    utils::GetLogger().Info("服务器开始监听", 
        utils::LogContext()
            .With("host", host)
            .With("port", std::to_string(port)));
    
    if (!server.listen(host.c_str(), port)) {
        utils::GetLogger().Fatal("无法启动服务器", 
            utils::LogContext()
                .With("host", host)
                .With("port", std::to_string(port)));
        return Error(1, "无法启动服务器"); // ErrUnknown
    }
    
    return Error();
}

void Server::handleHttpRequest(const std::string& method, const httplib::Request& req, httplib::Response& res) {
    // 记录请求开始
    utils::GetLogger().Debug("开始处理HTTP请求", 
        utils::LogContext()
            .With("method", method)
            .With("path", req.path)
            .With("remoteAddr", req.remote_addr));
    
    // 创建请求上下文
    Request request;
    request.method = method;
    request.path = req.path;
    request.body = req.body;
    
    // 转换headers
    for (const auto& header : req.headers) {
        request.headers[header.first] = header.second;
        
        // 记录重要的请求头
        if (header.first == "Content-Type" || 
            header.first == "Authorization" || 
            header.first == "User-Agent") {
            utils::GetLogger().Debug("请求头", 
                utils::LogContext()
                    .With("name", header.first)
                    .With("value", header.second));
        }
    }
    
    // 创建上下文
    Context ctx;
    ctx.request = request;
    ctx.cryptoService = config_.cryptoService;
    ctx.keyAlgorithm = config_.keyAlgorithm;
    ctx.storageService = config_.storageService;
    
    // 创建响应对象
    Response response;
    response.status = 200;
    
    // 处理请求
    Error err = router_.HandleRequest(ctx, response);
    
    // 设置响应状态码
    if (err.Code() != 0) { // 0 = NoError
        response.status = err.HTTPStatusCode();
        
        // 记录错误信息
        utils::GetLogger().Warn("请求处理出错", 
            utils::LogContext()
                .With("code", std::to_string(err.Code()))
                .With("message", err.Detail())
                .With("statusCode", std::to_string(response.status))
                .With("method", method)
                .With("path", req.path));
        
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
    } else {
        // 记录请求成功
        utils::GetLogger().Debug("请求处理成功", 
            utils::LogContext()
                .With("method", method)
                .With("path", req.path)
                .With("status", std::to_string(response.status)));
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