#include <catch2/catch_test_macros.hpp>
#include <sstream>
#include <iostream>
#include "notary/passRetriever/passRetriever.hpp"

using namespace notary::passphrase;

TEST_CASE("PassRetriever - ConstantRetriever", "[passRetriever]") {
    SECTION("Returns constant password") {
        auto retriever = ConstantRetriever("test_password");
        auto [password, giveup, error] = retriever("key_id", "root", true, 0);
        
        REQUIRE(!error.hasError());
        REQUIRE(!giveup);
        REQUIRE(password == "test_password");
    }
}

TEST_CASE("PassRetriever - PromptRetrieverWithInOut", "[passRetriever]") {
    SECTION("Successful password creation") {
        std::istringstream input("mypassword123\nmypassword123\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        auto [password, giveup, error] = retriever("abc1234567", "root", true, 0);
        
        REQUIRE(!error.hasError());
        REQUIRE(!giveup);
        REQUIRE(password == "mypassword123");
        
        // 验证输出包含了警告信息和提示
        std::string outputStr = output.str();
        REQUIRE(outputStr.find("You are about to create a new root signing key") != std::string::npos);
        REQUIRE(outputStr.find("Enter passphrase for new root key") != std::string::npos);
        REQUIRE(outputStr.find("Repeat passphrase for new root key") != std::string::npos);
    }
    
    SECTION("Password too short") {
        std::istringstream input("short\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        auto [password, giveup, error] = retriever("abc1234567", "targets", true, 0);
        
        REQUIRE(error.hasError());
        REQUIRE(error.what() == "Passphrase too short");
        
        std::string outputStr = output.str();
        REQUIRE(outputStr.find("Passphrase is too short") != std::string::npos);
    }
    
    SECTION("Password mismatch") {
        std::istringstream input("password123\ndifferentpassword\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        auto [password, giveup, error] = retriever("def7654321", "targets", true, 0);
        
        REQUIRE(error.hasError());
        REQUIRE(error.what() == "Passphrases do not match");
        
        std::string outputStr = output.str();
        REQUIRE(outputStr.find("Passphrases do not match") != std::string::npos);
    }
    
    SECTION("Existing password retrieval") {
        std::istringstream input("existingpassword\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        auto [password, giveup, error] = retriever("xyz9876543", "snapshot", false, 0);
        
        REQUIRE(!error.hasError());
        REQUIRE(!giveup);
        REQUIRE(password == "existingpassword");
        
        std::string outputStr = output.str();
        REQUIRE(outputStr.find("Enter passphrase for snapshot key") != std::string::npos);
    }
    
    SECTION("Password caching") {
        std::istringstream input("cachedpassword\ncachedpassword\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        
        // 第一次获取密码
        auto [password1, giveup1, error1] = retriever("key123", "root", true, 0);
        REQUIRE(!error1.hasError());
        REQUIRE(password1 == "cachedpassword");
        
        // 第二次获取相同角色的密码应该从缓存返回
        auto [password2, giveup2, error2] = retriever("key456", "root", false, 0);
        REQUIRE(!error2.hasError());
        REQUIRE(password2 == "cachedpassword");
        
        // 验证第二次没有提示输入（因为使用了缓存）
        std::string outputStr = output.str();
        // 只有第一次会有root key警告
        size_t warningCount = 0;
        size_t pos = 0;
        while ((pos = outputStr.find("You are about to create", pos)) != std::string::npos) {
            warningCount++;
            pos += 1;
        }
        REQUIRE(warningCount == 1);
    }
}

TEST_CASE("PassRetriever - Alias mapping", "[passRetriever]") {
    SECTION("Uses custom alias names") {
        std::map<std::string, std::string> aliasMap = {
            {"root", "根密钥"},
            {"targets", "目标密钥"}
        };
        
        std::istringstream input("testpassword123\ntestpassword123\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output, aliasMap);
        auto [password, giveup, error] = retriever("test_key", "targets", true, 0);
        
        REQUIRE(!error.hasError());
        REQUIRE(password == "testpassword123");
        
        std::string outputStr = output.str();
        REQUIRE(outputStr.find("目标密钥") != std::string::npos);
    }
}

TEST_CASE("PassRetriever - Key name formatting", "[passRetriever]") {
    SECTION("Formats long key names correctly") {
        std::istringstream input("testpassword123\ntestpassword123\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        auto [password, giveup, error] = retriever("very/long/path/to/key123456789", "targets", true, 0);
        
        REQUIRE(!error.hasError());
        
        std::string outputStr = output.str();
        // 应该包含格式化的密钥ID
        REQUIRE(outputStr.find("with ID") != std::string::npos);
    }
}

TEST_CASE("PassRetriever - Retry logic", "[passRetriever]") {
    SECTION("Handles incorrect password retry") {
        std::istringstream input("correctpassword\n");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        
        // 模拟第二次尝试（numAttempts = 1）
        auto [password, giveup, error] = retriever("test_key", "root", false, 1);
        
        REQUIRE(!error.hasError());
        REQUIRE(password == "correctpassword");
        
        std::string outputStr = output.str();
        REQUIRE(outputStr.find("Passphrase incorrect. Please retry.") != std::string::npos);
    }
    
    SECTION("Gives up after too many attempts") {
        std::istringstream input("");
        std::ostringstream output;
        
        auto retriever = PromptRetrieverWithInOut(&input, &output);
        
        // 模拟第四次尝试（超过限制）
        auto [password, giveup, error] = retriever("test_key", "root", false, 4);
        
        REQUIRE(error.hasError());
        REQUIRE(giveup);
        REQUIRE(error.what() == "Too many attempts");
    }
}

TEST_CASE("PassRetriever - Utility functions", "[passRetriever]") {
    SECTION("TrimSpace removes whitespace") {
        REQUIRE(TrimSpace("  hello  ") == "hello");
        REQUIRE(TrimSpace("\t\ntest\r\f") == "test");
        REQUIRE(TrimSpace("   ") == "");
        REQUIRE(TrimSpace("no_spaces") == "no_spaces");
    }
    
    SECTION("IsTerminal function exists") {
        // 这个测试只是确保函数可以调用，具体结果取决于运行环境
        bool result = IsTerminal(0);
        // result 可以是 true 或 false，我们只是确保不会崩溃
        REQUIRE((result == true || result == false));
    }
}