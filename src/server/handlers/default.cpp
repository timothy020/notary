#include "notary/server/server.hpp"
#include <nlohmann/json.hpp>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "notary/utils/logger.hpp"

namespace notary {
namespace server {
namespace handlers {

// 定义用于元数据更新的结构体
struct MetaUpdate {
    RoleName role;
    std::string roleName;
    int version;
    std::string data;
};

// 主页处理程序
Error MainHandler(const Context& ctx, Response& resp) {
    utils::GetLogger().Debug("处理主页请求");
    resp.body = "{}";
    resp.headers["Content-Type"] = "application/json";
    return Error();
}

// 404处理程序
Error NotFoundHandler(const Context& ctx, Response& resp) {
    utils::GetLogger().Warn("资源未找到", 
        utils::LogContext()
            .With("method", ctx.request.method)
            .With("path", ctx.request.path));
    
    resp.status = 404;
    resp.body = "{\"errors\":[{\"code\":\"NOT_FOUND\",\"message\":\"Resource not found\"}]}";
    resp.headers["Content-Type"] = "application/json";
    return Error::ErrMetadataNotFound;
}

// 处理获取密钥请求
Error GetKeyHandler(const Context& ctx, Response& resp) {
    // 提取参数
    const auto& params = ctx.request.params;
    
    auto gunIt = params.find("gun");
    auto roleIt = params.find("tufRole");
    
    if (gunIt == params.end() || roleIt == params.end()) {
        utils::GetLogger().Error("获取密钥请求缺少必要参数", 
            utils::LogContext()
                .With("params", "gun, tufRole"));
        return Error(4, "缺少必要的参数"); // ErrInvalidRole
    }
    
    const std::string& gun = gunIt->second;
    const std::string& roleName = roleIt->second;
    
    utils::GetLogger().Info("处理获取密钥请求", 
        utils::LogContext()
            .With("gun", gun)
            .With("role", roleName));
    
    // 检查角色名是否有效
    RoleName role;
    if (roleName == "timestamp") {
        role = RoleName::TimestampRole;
    } else if (roleName == "snapshot") {
        role = RoleName::SnapshotRole;
    } else {
        utils::GetLogger().Error("不支持的角色", 
            utils::LogContext().With("role", roleName));
        return Error(4, "不支持的角色: " + roleName); // ErrInvalidRole
    }
    
    // 检查加密服务是否可用
    if (!ctx.cryptoService) {
        utils::GetLogger().Error("加密服务不可用");
        return Error::ErrNoCryptoService;
    }
    
    // 检查算法
    if (ctx.keyAlgorithm.empty()) {
        utils::GetLogger().Error("未指定密钥算法");
        return Error::ErrNoKeyAlgorithm;
    }
    
    // 解析算法
    KeyAlgorithm algo = KeyAlgorithm::ECDSA;
    if (ctx.keyAlgorithm == "ecdsa") {
        algo = KeyAlgorithm::ECDSA;
    } else if (ctx.keyAlgorithm == "rsa") {
        algo = KeyAlgorithm::RSA;
    } else if (ctx.keyAlgorithm == "ed25519") {
        algo = KeyAlgorithm::ED25519;
    } else {
        utils::GetLogger().Error("不支持的算法", 
            utils::LogContext().With("algorithm", ctx.keyAlgorithm));
        return Error(10, "不支持的算法: " + ctx.keyAlgorithm); // ErrNoKeyAlgorithm
    }
    
    // 获取或创建密钥
    utils::GetLogger().Debug("获取或创建密钥", 
        utils::LogContext()
            .With("gun", gun)
            .With("role", roleName)
            .With("algorithm", ctx.keyAlgorithm));
    
    auto keyResult = ctx.cryptoService->Create(role, gun, algo);
    if (!keyResult.ok()) {
        utils::GetLogger().Error("创建密钥失败", 
            utils::LogContext().With("error", keyResult.error().what()));
        return Error(1, keyResult.error().what()); // ErrUnknown
    }
    
    auto key = keyResult.value();
    
    // 创建响应
    json keyJson;
    if (algo == KeyAlgorithm::ECDSA) {
        auto ecdsaKey = std::dynamic_pointer_cast<crypto::ECDSAPublicKey>(key);
        if (ecdsaKey) {
            const auto& derData = ecdsaKey->GetDERData();
            
            // Base64编码DER数据
            std::string keyData;
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO* mem = BIO_new(BIO_s_mem());
            BIO_push(b64, mem);
            BIO_write(b64, derData.data(), derData.size());
            BIO_flush(b64);
            BUF_MEM* bptr;
            BIO_get_mem_ptr(b64, &bptr);
            keyData = std::string(bptr->data, bptr->length);
            BIO_free_all(b64);
            
            try {
                keyJson = {
                    {"keytype", "ecdsa"},
                    {"keyval", {
                        {"public", keyData},
                        {"private", nullptr}
                    }}
                };
            } catch (const std::exception& e) {
                utils::GetLogger().Error("JSON序列化错误", 
                    utils::LogContext().With("error", e.what()));
                return Error(1, "JSON序列化错误: " + std::string(e.what()));
            }
        } else {
            utils::GetLogger().Error("密钥类型转换失败");
            return Error(1, "密钥类型转换失败"); // ErrUnknown
        }
    } else {
        utils::GetLogger().Error("目前仅支持ECDSA密钥",
            utils::LogContext().With("requestedType", ctx.keyAlgorithm));
        return Error(10, "目前仅支持ECDSA密钥"); // ErrNoKeyAlgorithm
    }
    
    try {
        resp.body = keyJson.dump();
        resp.headers["Content-Type"] = "application/json";
        utils::GetLogger().Info("成功创建密钥", 
            utils::LogContext()
                .With("keyID", key->ID())
                .With("gun", gun)
                .With("role", roleName));
    } catch (const std::exception& e) {
        utils::GetLogger().Error("JSON转换错误", 
            utils::LogContext().With("error", e.what()));
        return Error(1, "JSON转换错误: " + std::string(e.what()));
    }
    
    return Error();
}

// 处理轮换密钥请求
Error RotateKeyHandler(const Context& ctx, Response& resp) {
    utils::GetLogger().Info("处理轮换密钥请求", 
        utils::LogContext()
            .With("gun", ctx.request.params.count("gun") ? ctx.request.params.at("gun") : "")
            .With("role", ctx.request.params.count("tufRole") ? ctx.request.params.at("tufRole") : ""));
    
    // 基本上与GetKeyHandler相同，但会强制创建新密钥
    return GetKeyHandler(ctx, resp);
}

// 处理原子更新请求
Error AtomicUpdateHandler(const Context& ctx, Response& resp) {
    // 提取gun参数
    const auto& params = ctx.request.params;
    auto gunIt = params.find("gun");
    
    if (gunIt == params.end()) {
        utils::GetLogger().Error("更新元数据请求缺少必要参数",
            utils::LogContext().With("params", "gun"));
        return Error(4, "缺少必要的参数"); // ErrInvalidGUN
    }
    
    const std::string& gun = gunIt->second;
    
    utils::GetLogger().Info("处理原子更新请求", 
        utils::LogContext()
            .With("gun", gun)
            .With("contentLength", std::to_string(ctx.request.body.size())));
    
    // 检查存储服务是否可用
    if (!ctx.storageService) {
        utils::GetLogger().Error("存储服务不可用");
        return Error::ErrNoStorage;
    }
    
    // 检查加密服务是否可用
    if (!ctx.cryptoService) {
        utils::GetLogger().Error("加密服务不可用");
        return Error::ErrNoCryptoService;
    }
    
    // 检查Content-Type，确保是multipart/form-data
    auto contentTypeIt = ctx.request.headers.find("Content-Type");
    if (contentTypeIt == ctx.request.headers.end() || 
        contentTypeIt->second.find("multipart/form-data") == std::string::npos) {
        utils::GetLogger().Error("请求不是multipart/form-data格式",
            utils::LogContext().With("contentType", 
                contentTypeIt != ctx.request.headers.end() ? contentTypeIt->second : "未指定"));
        return Error(5, "无效的请求格式，需要multipart/form-data"); // ErrMalformedUpload
    }
    
    // 解析boundary
    std::string boundary;
    size_t boundaryPos = contentTypeIt->second.find("boundary=");
    if (boundaryPos != std::string::npos) {
        boundary = contentTypeIt->second.substr(boundaryPos + 9); // 9是"boundary="的长度
        // 处理引号
        if (!boundary.empty() && boundary.front() == '"' && boundary.back() == '"') {
            boundary = boundary.substr(1, boundary.size() - 2);
        }
    } else {
        utils::GetLogger().Error("无法解析multipart/form-data boundary");
        return Error(5, "无法解析multipart/form-data boundary"); // ErrMalformedUpload
    }
    
    // 存储所有角色的更新
    std::vector<MetaUpdate> updates;
    
    try {
        // 解析multipart数据
        const std::string& body = ctx.request.body;
        std::string delimiter = "--" + boundary;
        std::string closeDelimiter = delimiter + "--";
        
        size_t pos = body.find(delimiter);
        while (pos != std::string::npos) {
            // 移动到分隔符之后
            pos += delimiter.size();
            
            // 检查是否是结束分隔符
            if (body.compare(pos, closeDelimiter.size() - delimiter.size(), "--") == 0) {
                break;
            }
            
            // 跳过换行符
            if (body[pos] == '\r') pos++;
            if (body[pos] == '\n') pos++;
            
            // 找到下一个分隔符位置
            size_t nextPos = body.find(delimiter, pos);
            if (nextPos == std::string::npos) {
                nextPos = body.find(closeDelimiter, pos);
                if (nextPos == std::string::npos) {
                    utils::GetLogger().Error("无法找到multipart分隔符");
                    return Error(5, "无法解析multipart/form-data数据"); // ErrMalformedUpload
                }
            }
            
            // 提取part内容
            std::string part = body.substr(pos, nextPos - pos);
            
            // 提取Content-Disposition和filename
            size_t headerEnd = part.find("\r\n\r\n");
            if (headerEnd == std::string::npos) {
                utils::GetLogger().Error("无法解析part头");
                return Error(5, "无法解析multipart/form-data part头"); // ErrMalformedUpload
            }
            
            std::string header = part.substr(0, headerEnd);
            std::string content = part.substr(headerEnd + 4); // 跳过"\r\n\r\n"
            
            // 提取filename参数
            size_t filenamePos = header.find("filename=");
            if (filenamePos == std::string::npos) {
                utils::GetLogger().Error("无法找到filename参数");
                return Error(6, "请求缺少filename参数"); // ErrNoFilename
            }
            
            size_t filenameStart = header.find("\"", filenamePos) + 1;
            size_t filenameEnd = header.find("\"", filenameStart);
            std::string filename = header.substr(filenameStart, filenameEnd - filenameStart);
            
            // 去除.json后缀获取角色名
            std::string roleName = filename;
            size_t jsonSuffix = roleName.rfind(".json");
            if (jsonSuffix != std::string::npos) {
                roleName = roleName.substr(0, jsonSuffix);
            }
            
            // 验证角色名是否有效
            if (roleName.empty()) {
                utils::GetLogger().Info("角色名为空");
                return Error(6, "角色名为空"); // ErrNoFilename
            }
            
            // 确定角色类型
            RoleName role;
            bool validRole = true;
            
            if (roleName == "root") {
                role = RoleName::RootRole;
            } else if (roleName == "targets" || roleName.find("targets/") == 0) {
                role = RoleName::TargetsRole;
            } else if (roleName == "snapshot") {
                role = RoleName::SnapshotRole;
            } else if (roleName == "timestamp") {
                role = RoleName::TimestampRole;
            } else {
                validRole = false;
            }
            
            if (!validRole) {
                utils::GetLogger().Info("无效的角色名", 
                    utils::LogContext().With("role", roleName));
                return Error(4, "无效的角色名: " + roleName); // ErrInvalidRole
            }
            
            // 解析元数据JSON
            try {
                // 解析JSON以获取版本号
                auto j = json::parse(content);
                auto signed_data = j["signed"];
                
                if (!signed_data.contains("_type") || !signed_data.contains("version")) {
                    utils::GetLogger().Error("元数据JSON格式错误，缺少_type或version字段");
                    return Error(7, "元数据JSON格式错误"); // ErrMalformedJSON
                }
                
                int version = signed_data["version"].get<int>();
                
                // 创建MetaUpdate对象
                MetaUpdate update;
                update.role = role;
                update.roleName = roleName;
                update.version = version;
                update.data = content;
                
                updates.push_back(update);
                
                utils::GetLogger().Debug("解析元数据成功", 
                    utils::LogContext()
                        .With("role", roleName)
                        .With("version", std::to_string(version)));
                
            } catch (const json::exception& e) {
                utils::GetLogger().Error("解析JSON失败", 
                    utils::LogContext()
                        .With("error", e.what())
                        .With("role", roleName));
                return Error(7, "无法解析元数据JSON: " + std::string(e.what())); // ErrMalformedJSON
            }
            
            // 更新位置到下一个分隔符
            pos = nextPos;
        }
        
        // 验证更新
        // TODO: 实现validateUpdate函数，验证元数据签名和版本
        // 这里应该有类似Go代码中validateUpdate的实现
        // 验证失败时应该返回适当的错误
        
        // 一次性更新所有元数据
        for (const auto& update : updates) {
            auto result = ctx.storageService->StoreMetadata(gun, update.role, update.roleName, update.data);
            if (!result.ok()) {
                // 处理版本冲突
                // 假设Error::ErrOldVersion是版本冲突错误码
                if (result.error().what().find("Old version") != std::string::npos) {
                    utils::GetLogger().Info("版本冲突", 
                        utils::LogContext()
                            .With("gun", gun)
                            .With("role", update.roleName));
                    return Error(8, "版本冲突: " + result.error().what()); // ErrOldVersion
                }
                
                utils::GetLogger().Error("存储元数据失败", 
                    utils::LogContext()
                        .With("gun", gun)
                        .With("role", update.roleName)
                        .With("error", result.error().what()));
                return Error(9, "更新失败: " + result.error().what()); // ErrUpdating
            }
        }
        
        // 记录更新信息
        for (const auto& update : updates) {
            utils::GetLogger().Info("更新元数据成功", 
                utils::LogContext()
                    .With("gun", gun)
                    .With("role", update.roleName)
                    .With("version", std::to_string(update.version)));
        }
        
        // 返回成功响应
        resp.body = "{}";
        resp.headers["Content-Type"] = "application/json";
        return Error();
        
    } catch (const std::exception& e) {
        utils::GetLogger().Error("处理原子更新请求失败", 
            utils::LogContext()
                .With("gun", gun)
                .With("error", e.what()));
        return Error(1, "处理原子更新请求失败: " + std::string(e.what())); // ErrUnknown
    }
}

// 处理获取元数据请求
Error GetHandler(const Context& ctx, Response& resp) {
    // 提取请求参数
    const auto& params = ctx.request.params;
    const auto& path = ctx.request.path;
    
    auto gunIt = params.find("gun");
    auto tufRoleIt = params.find("tufRole");
    auto checksumIt = params.find("checksum");
    auto versionIt = params.find("version");
    auto delegatedRoleIt = params.find("delegatedRole");
    
    if (gunIt == params.end()) {
        utils::GetLogger().Error("获取元数据请求缺少必要参数", 
            utils::LogContext().With("params", "gun"));
        return Error::ErrMetadataNotFound;
    }
    
    const std::string& gun = gunIt->second;
    std::string tufRole;
    
    // 确定角色名称
    if (tufRoleIt != params.end()) {
        // 参数中有明确的角色
        tufRole = tufRoleIt->second;
    } else if (delegatedRoleIt != params.end()) {
        // 处理委托目标
        tufRole = "targets/" + delegatedRoleIt->second;
    } else {
        // 从URL路径中提取角色
        // 形如 "/v2/example.com/_trust/tuf/root.json" 或 "/v2/example.com/_trust/tuf/1.root.json"
        std::string rolePart;
        
        size_t lastSlashPos = path.find_last_of('/');
        if (lastSlashPos != std::string::npos) {
            rolePart = path.substr(lastSlashPos + 1);
        }
        
        // 移除.json后缀
        size_t jsonPos = rolePart.find(".json");
        if (jsonPos != std::string::npos) {
            rolePart = rolePart.substr(0, jsonPos);
        }
        
        // 移除校验和部分
        size_t checksumPos = rolePart.find('.');
        if (checksumPos != std::string::npos && checksumIt != params.end()) {
            rolePart = rolePart.substr(0, checksumPos);
        }
        
        // 处理版本号格式 (e.g. "1.root")
        if (versionIt != params.end() && checksumPos != std::string::npos) {
            rolePart = rolePart.substr(checksumPos + 1);
        }
        
        // 现在rolePart应该包含角色名称
        if (rolePart == "root" || rolePart == "targets" || 
            rolePart == "snapshot" || rolePart == "timestamp") {
            tufRole = rolePart;
        } else {
            utils::GetLogger().Error("无法从路径中提取角色", 
                utils::LogContext().With("path", path));
            return Error::ErrMetadataNotFound;
        }
    }
    
    const std::string checksum = checksumIt != params.end() ? checksumIt->second : "";
    const std::string versionStr = versionIt != params.end() ? versionIt->second : "";
    
    int version = 0;
    if (!versionStr.empty()) {
        try {
            version = std::stoi(versionStr);
        } catch (const std::exception& e) {
            utils::GetLogger().Error("版本号解析错误", 
                utils::LogContext()
                    .With("version", versionStr)
                    .With("error", e.what()));
            return Error::ErrMetadataNotFound;
        }
    }
    
    utils::GetLogger().Info("处理获取元数据请求", 
        utils::LogContext()
            .With("gun", gun)
            .With("role", tufRole)
            .With("checksum", checksum)
            .With("version", versionStr));
    
    // 检查存储服务是否可用
    if (!ctx.storageService) {
        utils::GetLogger().Error("存储服务不可用");
        return Error::ErrNoStorage;
    }
    
    // 确定角色
    RoleName role;
    if (tufRole == "root") {
        role = RoleName::RootRole;
    } else if (tufRole == "targets" || tufRole.find("targets/") == 0) {
        role = RoleName::TargetsRole;
    } else if (tufRole == "snapshot") {
        role = RoleName::SnapshotRole;
    } else if (tufRole == "timestamp") {
        role = RoleName::TimestampRole;
    } else {
        utils::GetLogger().Error("不支持的角色", 
            utils::LogContext().With("role", tufRole));
        return Error::ErrMetadataNotFound;
    }
    
    // 创建元数据请求
    MetadataRequest metadataRequest;
    metadataRequest.gun = gun;
    metadataRequest.role = role;
    metadataRequest.roleName = tufRole;
    metadataRequest.checksum = checksum;
    metadataRequest.version = version;
    
    // 获取元数据
    auto result = ctx.storageService->GetMetadata(metadataRequest);
    if (!result.ok()) {
        utils::GetLogger().Error("获取元数据失败", 
            utils::LogContext()
                .With("gun", gun)
                .With("role", tufRole)
                .With("error", result.error().what()));
    return Error::ErrMetadataNotFound;
    }
    
    const auto& metadata = result.value();
    
    // 设置响应内容
    resp.body = metadata.data;
    resp.headers["Content-Type"] = "application/json";
    
    // 设置缓存控制和最后修改时间
    auto lastModified = metadata.timestamp;
    if (lastModified.time_since_epoch().count() > 0) {
        auto lastModifiedTime = std::chrono::system_clock::to_time_t(lastModified);
        std::tm* tm = std::gmtime(&lastModifiedTime);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", tm);
        resp.headers["Last-Modified"] = buf;
    }
    
    // 默认设置一小时缓存（可根据角色不同调整）
    resp.headers["Cache-Control"] = "max-age=3600";
    
    utils::GetLogger().Info("元数据获取成功", 
        utils::LogContext()
            .With("gun", gun)
            .With("role", tufRole)
            .With("version", std::to_string(metadata.version))
            .With("checksum", metadata.checksum)
            .With("size", std::to_string(metadata.data.size())));
    
    return Error();
}

// 处理删除请求
Error DeleteHandler(const Context& ctx, Response& resp) {
    utils::GetLogger().Info("处理删除请求", 
        utils::LogContext()
            .With("gun", ctx.request.params.count("gun") ? ctx.request.params.at("gun") : ""));
    
    // 暂时简单实现，返回成功
    resp.body = "{}";
    resp.headers["Content-Type"] = "application/json";
    return Error();
}

} // namespace handlers
} // namespace server
} // namespace notary 