#pragma once

#include <string>
#include <map>
#include <memory>
#include <functional>
#include <iostream>
#include <tuple>
#include "notary/types.hpp"

namespace notary {
namespace passphrase {

// 常量定义
constexpr int ID_BYTES_TO_DISPLAY = 7;
constexpr const char* TUF_ROOT_ALIAS = "root";
constexpr const char* TUF_ROOT_KEY_GENERATION_WARNING = 
    "You are about to create a new root signing key passphrase. This passphrase\n"
    "will be used to protect the most sensitive key in your signing system. Please\n"
    "choose a long, complex passphrase and be careful to keep the password and the\n"
    "key file itself secure and backed up. It is highly recommended that you use a\n"
    "password manager to generate the passphrase and keep it safe. There will be no\n"
    "way to recover this key. You can find the key in your config directory.";

// 错误类型定义
class PassphraseError : public std::exception {
private:
    std::string message_;
public:
    explicit PassphraseError(const std::string& msg) : message_(msg) {}
    const char* what() const noexcept override { return message_.c_str(); }
};

class ErrTooShort : public PassphraseError {
public:
    ErrTooShort() : PassphraseError("passphrase too short") {}
};

class ErrDontMatch : public PassphraseError {
public:
    ErrDontMatch() : PassphraseError("the entered passphrases do not match") {}
};

class ErrTooManyAttempts : public PassphraseError {
public:
    ErrTooManyAttempts() : PassphraseError("too many attempts") {}
};

class ErrNoInput : public PassphraseError {
public:
    ErrNoInput() : PassphraseError("please either use environment variables or STDIN with a terminal to provide key passphrases") {}
};

// PassRetriever 函数类型定义
// 返回值：tuple<passphrase, giveup, error>
using PassRetriever = std::function<std::tuple<std::string, bool, Error>(
    const std::string& keyName, 
    const std::string& alias, 
    bool createNew, 
    int numAttempts
)>;

// BoundRetriever 类定义
class BoundRetriever {
private:
    std::istream* in_;
    std::ostream* out_;
    std::map<std::string, std::string> aliasMap_;
    std::map<std::string, std::string> passphraseCache_;

public:
    BoundRetriever(std::istream* in, std::ostream* out, 
                   const std::map<std::string, std::string>& aliasMap = {});

    // 主要的密码获取方法
    std::tuple<std::string, bool, Error> getPassphrase(
        const std::string& keyName, 
        const std::string& alias, 
        bool createNew, 
        int numAttempts
    );

private:
    // 请求密码输入
    std::tuple<std::string, bool, Error> requestPassphrase(
        const std::string& keyName, 
        const std::string& alias, 
        bool createNew, 
        int numAttempts
    );

    // 验证和确认密码
    Error verifyAndConfirmPassword(
        const std::string& retPass, 
        const std::string& displayAlias, 
        const std::string& withID
    );

    // 缓存密码
    void cachePassword(const std::string& alias, const std::string& retPass);

    // 格式化密钥显示名称
    std::string formatKeyName(const std::string& keyName) const;
};

// 工厂函数声明

// 创建提示型密码获取器（检查终端）
PassRetriever PromptRetriever();

// 创建指定输入输出的密码获取器
PassRetriever PromptRetrieverWithInOut(
    std::istream* in, 
    std::ostream* out, 
    const std::map<std::string, std::string>& aliasMap = {}
);

// 创建常量密码获取器
PassRetriever ConstantRetriever(const std::string& constantPassphrase);

// 底层密码读取函数
std::tuple<std::string, Error> GetPassphrase(std::istream* in = nullptr);

// 辅助函数
bool IsTerminal(int fd);
std::string TrimSpace(const std::string& str);

} // namespace passphrase
} // namespace notary
