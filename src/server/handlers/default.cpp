#include "notary/server/server.hpp"
#include <nlohmann/json.hpp>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace notary {
namespace server {
namespace handlers {

// 主页处理程序
Error MainHandler(const Context& ctx, Response& resp) {
    resp.body = "{}";
    resp.headers["Content-Type"] = "application/json";
    return Error();
}

// 404处理程序
Error NotFoundHandler(const Context& ctx, Response& resp) {
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
        return Error(4, "缺少必要的参数"); // ErrInvalidRole
    }
    
    const std::string& gun = gunIt->second;
    const std::string& roleName = roleIt->second;
    
    // 检查角色名是否有效
    RoleName role;
    if (roleName == "timestamp") {
        role = RoleName::TimestampRole;
    } else if (roleName == "snapshot") {
        role = RoleName::SnapshotRole;
    } else {
        return Error(4, "不支持的角色: " + roleName); // ErrInvalidRole
    }
    std::cout << "获取或创建" << gun << "的" << roleName << "密钥" << std::endl;
    
    // 检查加密服务是否可用
    if (!ctx.cryptoService) {
        return Error::ErrNoCryptoService;
    }
    
    // 检查算法
    if (ctx.keyAlgorithm.empty()) {
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
        return Error(10, "不支持的算法: " + ctx.keyAlgorithm); // ErrNoKeyAlgorithm
    }
    
    // 获取或创建密钥
    std::cout << "获取或创建" << gun << "的" << roleName << "密钥" << std::endl;
    auto keyResult = ctx.cryptoService->Create(role, gun, algo);
    if (!keyResult.ok()) {
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
                std::cerr << "JSON序列化错误: " << e.what() << std::endl;
                return Error(1, "JSON序列化错误: " + std::string(e.what()));
            }
        } else {
            return Error(1, "密钥类型转换失败"); // ErrUnknown
        }
    } else {
        return Error(10, "目前仅支持ECDSA密钥"); // ErrNoKeyAlgorithm
    }
    
    try {
        resp.body = keyJson.dump();
        resp.headers["Content-Type"] = "application/json";
        std::cout << "成功创建密钥: " << key->ID() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "JSON转换错误: " << e.what() << std::endl;
        return Error(1, "JSON转换错误: " + std::string(e.what()));
    }
    
    return Error();
}

// 处理轮换密钥请求
Error RotateKeyHandler(const Context& ctx, Response& resp) {
    // 基本上与GetKeyHandler相同，但会强制创建新密钥
    return GetKeyHandler(ctx, resp);
}

// 处理原子更新请求
Error AtomicUpdateHandler(const Context& ctx, Response& resp) {
    // 这个函数处理客户端提交的元数据更新
    // 暂时简单实现，返回成功
    resp.body = "{}";
    resp.headers["Content-Type"] = "application/json";
    return Error();
}

// 处理获取元数据请求
Error GetHandler(const Context& ctx, Response& resp) {
    // 暂时简单实现，返回404
    return Error::ErrMetadataNotFound;
}

// 处理删除请求
Error DeleteHandler(const Context& ctx, Response& resp) {
    // 暂时简单实现，返回成功
    resp.body = "{}";
    resp.headers["Content-Type"] = "application/json";
    return Error();
}

} // namespace handlers
} // namespace server
} // namespace notary 