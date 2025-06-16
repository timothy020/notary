#include "notary/passRetriever/passRetriever.hpp"
#include "notary/utils/logger.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

namespace notary {
namespace passphrase {

// 构造函数
BoundRetriever::BoundRetriever(std::istream* in, std::ostream* out, 
                               const std::map<std::string, std::string>& aliasMap)
    : in_(in), out_(out), aliasMap_(aliasMap) {
    if (!in_) in_ = &std::cin;
    if (!out_) out_ = &std::cout;
}

// 主要的密码获取方法
std::tuple<std::string, bool, Error> BoundRetriever::getPassphrase(
    const std::string& keyName, 
    const std::string& alias, 
    bool createNew, 
    int numAttempts) {
    
    if (numAttempts == 0) {
        // 如果是root角色的新密钥，显示警告信息
        if (alias == TUF_ROOT_ALIAS && createNew) {
            *out_ << TUF_ROOT_KEY_GENERATION_WARNING << std::endl;
        }

        // 检查缓存
        auto it = passphraseCache_.find(alias);
        if (it != passphraseCache_.end()) {
            return std::make_tuple(it->second, false, Error());
        }
    } else if (!createNew) { // numAttempts > 0 and not creating new
        if (numAttempts > 3) {
            return std::make_tuple("", true, Error("Too many attempts"));
        }
        *out_ << "Passphrase incorrect. Please retry." << std::endl;
    }

    // 缓存中没有密码且没有放弃，从用户获取密码
    return requestPassphrase(keyName, alias, createNew, numAttempts);
}

// 请求密码输入
std::tuple<std::string, bool, Error> BoundRetriever::requestPassphrase(
    const std::string& keyName, 
    const std::string& alias, 
    bool createNew, 
    int numAttempts) {
    
    // 确定显示别名
    std::string displayAlias = alias;
    auto it = aliasMap_.find(alias);
    if (it != aliasMap_.end()) {
        displayAlias = it->second;
    }

    // 格式化密钥名称
    std::string shortName = formatKeyName(keyName);
    std::string withID = shortName.empty() ? "" : " with ID " + shortName;

    // 显示提示信息
    if (createNew) {
        *out_ << "Enter passphrase for new " << displayAlias << " key" << withID << ": ";
    } else if (displayAlias == "yubikey") {
        *out_ << "Enter the " << keyName << " for the attached Yubikey: ";
    } else {
        *out_ << "Enter passphrase for " << displayAlias << " key" << withID << ": ";
    }
    out_->flush();

    // 获取密码
    auto [passphrase, err] = GetPassphrase(in_);
    *out_ << std::endl;
    
    if (err.hasError()) {
        return std::make_tuple("", false, err);
    }

    std::string retPass = TrimSpace(passphrase);

    // 如果是创建新密钥，需要验证和确认密码
    if (createNew) {
        Error verifyErr = verifyAndConfirmPassword(retPass, displayAlias, withID);
        if (verifyErr.hasError()) {
            return std::make_tuple("", false, verifyErr);
        }
    }

    // 缓存密码
    cachePassword(alias, retPass);

    return std::make_tuple(retPass, false, Error());
}

// 验证和确认密码
Error BoundRetriever::verifyAndConfirmPassword(
    const std::string& retPass, 
    const std::string& displayAlias, 
    const std::string& withID) {
    
    // 检查密码长度
    if (retPass.length() < 8) {
        *out_ << "Passphrase is too short. Please use a password manager to generate and store a good random passphrase." << std::endl;
        return Error("Passphrase too short");
    }

    // 要求重复输入密码
    *out_ << "Repeat passphrase for new " << displayAlias << " key" << withID << ": ";
    out_->flush();

    auto [confirmation, err] = GetPassphrase(in_);
    *out_ << std::endl;
    
    if (err.hasError()) {
        return err;
    }

    std::string confirmationStr = TrimSpace(confirmation);

    // 检查密码是否匹配
    if (retPass != confirmationStr) {
        *out_ << "Passphrases do not match. Please retry." << std::endl;
        return Error("Passphrases do not match");
    }
    
    return Error(); // 成功
}

// 缓存密码
void BoundRetriever::cachePassword(const std::string& alias, const std::string& retPass) {
    passphraseCache_[alias] = retPass;
}

// 格式化密钥显示名称
std::string BoundRetriever::formatKeyName(const std::string& keyName) const {
    size_t lastSeparator = keyName.find_last_of('/');
    if (lastSeparator == std::string::npos) {
        lastSeparator = 0;
    }

    std::string shortName;
    if (keyName.length() > lastSeparator + ID_BYTES_TO_DISPLAY) {
        if (lastSeparator > 0) {
            std::string keyNamePrefix = keyName.substr(0, lastSeparator);
            std::string keyNameID = keyName.substr(lastSeparator + 1, ID_BYTES_TO_DISPLAY);
            shortName = keyNameID + " (" + keyNamePrefix + ")";
        } else {
            shortName = keyName.substr(lastSeparator, ID_BYTES_TO_DISPLAY);
        }
    }
    return shortName;
}

// 工厂函数实现

// 创建提示型密码获取器（检查终端）
PassRetriever PromptRetriever() {
    if (!IsTerminal(STDIN_FILENO)) {
        return [](const std::string&, const std::string&, bool, int) -> std::tuple<std::string, bool, Error> {
            return std::make_tuple("", false, Error("No input available"));
        };
    }
    return PromptRetrieverWithInOut(&std::cin, &std::cout);
}

// 创建指定输入输出的密码获取器
PassRetriever PromptRetrieverWithInOut(
    std::istream* in, 
    std::ostream* out, 
    const std::map<std::string, std::string>& aliasMap) {
    
    auto bound = std::make_shared<BoundRetriever>(in, out, aliasMap);
    
    return [bound](const std::string& keyName, const std::string& alias, 
                   bool createNew, int numAttempts) -> std::tuple<std::string, bool, Error> {
        return bound->getPassphrase(keyName, alias, createNew, numAttempts);
    };
}

// 创建常量密码获取器
PassRetriever ConstantRetriever(const std::string& constantPassphrase) {
    return [constantPassphrase](const std::string&, const std::string&, bool, int) -> std::tuple<std::string, bool, Error> {
        return std::make_tuple(constantPassphrase, false, Error());
    };
}

// 底层密码读取函数
std::tuple<std::string, Error> GetPassphrase(std::istream* in) {
    if (!in) in = &std::cin;
    
    std::string passphrase;
    
    if (IsTerminal(STDIN_FILENO)) {
        // 在终端中，禁用回显
        struct termios oldTermios, newTermios;
        tcgetattr(STDIN_FILENO, &oldTermios);
        newTermios = oldTermios;
        newTermios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &newTermios);
        
        // 读取密码
        std::getline(*in, passphrase);
        
        // 恢复终端设置
        tcsetattr(STDIN_FILENO, TCSANOW, &oldTermios);
    } else {
        // 非终端环境，直接读取
        std::getline(*in, passphrase);
    }
    
    if (in->fail() && !in->eof()) {
        return std::make_tuple("", Error("Failed to read passphrase"));
    }
    
    return std::make_tuple(passphrase, Error());
}

// 辅助函数实现

// 检查是否为终端
bool IsTerminal(int fd) {
    return isatty(fd) != 0;
}

// 去除字符串两端的空白字符
std::string TrimSpace(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}

} // namespace passphrase
} // namespace notary
