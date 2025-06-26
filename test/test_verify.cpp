// #include <catch2/catch_test_macros.hpp>
// #include "notary/crypto/verify.hpp"
// #include "notary/crypto/crypto_service.hpp"
// #include <chrono>

// using namespace notary::crypto;
// using namespace notary::tuf;

// TEST_CASE("Verify基础功能测试", "[verify]") {
    
//     SECTION("IsExpired时间验证") {
//         auto now = std::chrono::system_clock::now();
//         auto pastTime = now - std::chrono::hours(1);
//         auto futureTime = now + std::chrono::hours(1);
        
//         REQUIRE(IsExpired(pastTime) == true);
//         REQUIRE(IsExpired(futureTime) == false);
//         REQUIRE(IsExpired(now) == false); // 当前时间不算过期
//     }
    
//     SECTION("VerifyExpiry测试") {
//         SignedCommon signedCommon;
//         signedCommon.Version = 1;
        
//         // 测试未过期的情况
//         signedCommon.Expires = std::chrono::system_clock::now() + std::chrono::hours(1);
//         Error err = VerifyExpiry(signedCommon, notary::ROOT_ROLE);
//         REQUIRE_FALSE(err.hasError());
        
//         // 测试已过期的情况
//         signedCommon.Expires = std::chrono::system_clock::now() - std::chrono::hours(1);
//         err = VerifyExpiry(signedCommon, notary::ROOT_ROLE);
//         REQUIRE(err.hasError());
//         REQUIRE(err.what().find("expired") != std::string::npos);
//     }
    
//     SECTION("VerifyVersion测试") {
//         SignedCommon signedCommon;
        
//         // 测试版本满足要求的情况
//         signedCommon.Version = 5;
//         Error err = VerifyVersion(signedCommon, 3);
//         REQUIRE_FALSE(err.hasError());
        
//         // 测试版本相等的情况
//         err = VerifyVersion(signedCommon, 5);
//         REQUIRE_FALSE(err.hasError());
        
//         // 测试版本低于要求的情况
//         err = VerifyVersion(signedCommon, 10);
//         REQUIRE(err.hasError());
//         REQUIRE(err.what().find("lower than expected") != std::string::npos);
//     }
    
//     SECTION("验证器初始化测试") {
//         InitializeVerifiers();
        
//         // 检查是否注册了预期的验证器
//         REQUIRE(Verifiers.find(RSAPSSSignature) != Verifiers.end());
//         REQUIRE(Verifiers.find(RSAPKCS1v15Signature) != Verifiers.end());
//         REQUIRE(Verifiers.find(ECDSASignature) != Verifiers.end());
//         REQUIRE(Verifiers.find(EDDSASignature) != Verifiers.end());
//         REQUIRE(Verifiers.find(PyCryptoSignature) != Verifiers.end());
//     }
// }

// TEST_CASE("签名验证错误测试", "[verify][errors]") {
    
//     SECTION("空签名验证") {
//         Signed signedData;
//         // 不添加任何签名
        
//         BaseRole role;
//         role.SetName(notary::ROOT_ROLE);
//         role.SetThreshold(1);
        
//         Error err = VerifySignatures(signedData, role);
//         REQUIRE(err.hasError());
//         REQUIRE(err.what().find("no signatures") != std::string::npos);
//     }
    
//     SECTION("阈值测试") {
//         Signed signedData;
//         Signature sig;
//         sig.KeyID = "test-key-id";
//         sig.Method = RSAPSSSignature;
//         signedData.Signatures.push_back(sig);
        
//         BaseRole role;
//         role.SetName(notary::ROOT_ROLE);
//         role.SetThreshold(0); // 无效阈值
        
//         Error err = VerifySignatures(signedData, role);
//         REQUIRE(err.hasError());
//         REQUIRE(err.what().find("threshold") != std::string::npos);
//     }
// }

// TEST_CASE("验证器功能测试", "[verify][verifiers]") {
    
//     SECTION("RSA验证器基础测试") {
//         InitializeVerifiers();
        
//         // 获取RSA验证器
//         auto it = Verifiers.find(RSAPSSSignature);
//         REQUIRE(it != Verifiers.end());
        
//         // 创建一个简单的模拟公钥进行测试
//         // 注意：这个测试只验证接口调用，不验证实际的密码学操作
//         // 因为我们的实现返回"not implemented yet"
        
//         // TODO: 当实际实现完成后，添加真实的密码学验证测试
//     }
    
//     SECTION("不支持的签名方法测试") {
//         InitializeVerifiers();
        
//         // 测试不存在的验证器
//         auto it = Verifiers.find("unknown-signature-method");
//         REQUIRE(it == Verifiers.end());
//     }
// }

// TEST_CASE("哈希验证测试", "[verify][hash]") {
    
//     SECTION("基础哈希验证逻辑") {
//         // 这里测试的是我们实现的基础验证逻辑
//         // 实际的哈希计算由utils模块处理
        
//         std::vector<uint8_t> testData = {'h', 'e', 'l', 'l', 'o'};
//         std::string roleName = "test-role";
        
//         // 空哈希映射应该返回错误
//         std::map<std::string, std::vector<uint8_t>> emptyHashes;
        
//         // 注意：我们无法直接测试checkHashes方法，因为它是RepoBuilderImpl的私有方法
//         // 但我们可以通过public接口间接测试验证逻辑
//     }
// } 