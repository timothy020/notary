#include "notary/passRetriever/passRetriever.hpp"
#include <iostream>
#include <sstream>

using namespace notary::passphrase;

int main() {
    std::cout << "=== C++ PassRetriever 示例 ===" << std::endl;
    
    // 示例1: 使用ConstantRetriever（用于测试）
    std::cout << "\n1. 使用常量密码获取器：" << std::endl;
    auto constantRetriever = ConstantRetriever("test_password");
    auto [password1, giveup1, error1] = constantRetriever("test_key", "root", true, 0);
    if (!error1.hasError()) {
        std::cout << "获取到密码: " << password1 << std::endl;
    } else {
        std::cout << "错误: " << error1.what() << std::endl;
    }

    // 示例2: 使用模拟输入的PromptRetrieverWithInOut
    std::cout << "\n2. 使用模拟输入的密码获取器（创建新密钥）：" << std::endl;
    std::istringstream input("mypassword123\nmypassword123\n"); // 模拟用户输入两次相同密码
    std::ostringstream output;
    
    auto promptRetriever = PromptRetrieverWithInOut(&input, &output);
    auto [password2, giveup2, error2] = promptRetriever("abc1234567", "root", true, 0);
    
    std::cout << "输出内容:" << std::endl;
    std::cout << output.str() << std::endl;
    
    if (!error2.hasError()) {
        std::cout << "成功获取密码，长度: " << password2.length() << std::endl;
    } else {
        std::cout << "错误: " << error2.what() << std::endl;
    }

    // 示例3: 密码不匹配的情况
    std::cout << "\n3. 测试密码不匹配的情况：" << std::endl;
    std::istringstream input2("password1\npassword2\n"); // 两次输入不同密码
    std::ostringstream output2;
    
    auto promptRetriever2 = PromptRetrieverWithInOut(&input2, &output2);
    auto [password3, giveup3, error3] = promptRetriever2("def7654321", "targets", true, 0);
    
    std::cout << "输出内容:" << std::endl;
    std::cout << output2.str() << std::endl;
    
    if (error3.hasError()) {
        std::cout << "预期的错误: " << error3.what() << std::endl;
    }

    // 示例4: 密码太短的情况
    std::cout << "\n4. 测试密码太短的情况：" << std::endl;
    std::istringstream input3("short\n"); // 密码太短
    std::ostringstream output3;
    
    auto promptRetriever3 = PromptRetrieverWithInOut(&input3, &output3);
    auto [password4, giveup4, error4] = promptRetriever3("ghi9876543", "snapshot", true, 0);
    
    std::cout << "输出内容:" << std::endl;
    std::cout << output3.str() << std::endl;
    
    if (error4.hasError()) {
        std::cout << "预期的错误: " << error4.what() << std::endl;
    }

    // 示例5: 使用别名映射
    std::cout << "\n5. 使用别名映射：" << std::endl;
    std::map<std::string, std::string> aliasMap = {
        {"root", "根密钥"},
        {"targets", "目标密钥"},
        {"snapshot", "快照密钥"}
    };
    
    std::istringstream input4("validpassword\nvalidpassword\n");
    std::ostringstream output4;
    
    auto promptRetriever4 = PromptRetrieverWithInOut(&input4, &output4, aliasMap);
    auto [password5, giveup5, error5] = promptRetriever4("jkl1357924", "targets", true, 0);
    
    std::cout << "输出内容:" << std::endl;
    std::cout << output4.str() << std::endl;
    
    if (!error5.hasError()) {
        std::cout << "成功获取密码，使用了中文别名显示" << std::endl;
    }

    // 示例6: 缓存测试
    std::cout << "\n6. 测试密码缓存：" << std::endl;
    std::istringstream input5("cachedpassword\ncachedpassword\n");
    std::ostringstream output5;
    
    auto promptRetriever5 = PromptRetrieverWithInOut(&input5, &output5);
    
    // 第一次获取密码（需要输入）
    auto [password6, giveup6, error6] = promptRetriever5("mno2468135", "root", true, 0);
    std::cout << "第一次获取，输出内容:" << std::endl;
    std::cout << output5.str() << std::endl;
    
    // 第二次获取相同角色的密码（应该从缓存获取）
    std::ostringstream output6;
    auto promptRetriever6 = PromptRetrieverWithInOut(&input5, &output6);
    
    // 由于我们创建了新的retriever，缓存不会延续。在实际使用中，同一个retriever实例会保持缓存
    
    std::cout << "\n=== PassRetriever 示例完成 ===" << std::endl;
    
    return 0;
} 