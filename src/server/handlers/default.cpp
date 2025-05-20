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
    utils::GetLogger().Info("处理原子更新请求", 
        utils::LogContext()
            .With("gun", ctx.request.params.count("gun") ? ctx.request.params.at("gun") : "")
            .With("contentLength", std::to_string(ctx.request.body.size())));
    
    // 这个函数处理客户端提交的元数据更新
    // 暂时简单实现，返回成功
    resp.body = "{}";
    resp.headers["Content-Type"] = "application/json";
    return Error();
}

// 处理获取元数据请求
Error GetHandler(const Context& ctx, Response& resp) {
    utils::GetLogger().Info("处理获取元数据请求", 
        utils::LogContext()
            .With("gun", ctx.request.params.count("gun") ? ctx.request.params.at("gun") : "")
            .With("role", ctx.request.params.count("tufRole") ? ctx.request.params.at("tufRole") : "")
            .With("version", ctx.request.params.count("version") ? ctx.request.params.at("version") : "")
            .With("checksum", ctx.request.params.count("checksum") ? ctx.request.params.at("checksum") : ""));
    
    // 暂时简单实现，返回404
    return Error::ErrMetadataNotFound;
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