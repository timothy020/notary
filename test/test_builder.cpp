// #include <catch2/catch_test_macros.hpp>
// #include "notary/tuf/builder.hpp"
// #include "notary/crypto/crypto_service.hpp"
// #include <memory>

// using namespace notary::tuf;
// using namespace notary::crypto;

// TEST_CASE("Builder基础功能测试", "[builder]") {
    
//     SECTION("创建新的RepoBuilder") {
//         std::string gun = "docker.com/test";
//         TrustPinConfig trustpin;
        
//         // 创建一个简单的CryptoService (可能需要mock)
//         auto cs = std::make_shared<CryptoService>();
        
//         auto builder = NewRepoBuilder(gun, cs, trustpin);
        
//         REQUIRE(builder != nullptr);
        
//         // 测试初始状态
//         REQUIRE_FALSE(builder->isLoaded(notary::RoleName::RootRole));
//         REQUIRE_FALSE(builder->isLoaded(notary::RoleName::TargetsRole));
//         REQUIRE_FALSE(builder->isLoaded(notary::RoleName::SnapshotRole));
//         REQUIRE_FALSE(builder->isLoaded(notary::RoleName::TimestampRole));
        
//         // 测试版本获取（未加载时应该返回1）
//         REQUIRE(builder->getLoadedVersion(notary::RoleName::RootRole) == 1);
//         REQUIRE(builder->getLoadedVersion(notary::RoleName::TargetsRole) == 1);
//     }
    
//     SECTION("ConsistentInfo功能测试") {
//         notary::RoleName role = notary::RoleName::RootRole;
//         ConsistentInfo info(role);
        
//         REQUIRE(info.getRoleName() == role);
//         REQUIRE_FALSE(info.checksumKnown());
//         REQUIRE(info.length() == -1);
        
//         // 设置FileMeta
//         notary::FileMeta meta;
//         meta.Length = 1024;
//         meta.Hashes["sha256"] = {0x01, 0x02, 0x03, 0x04}; // 简单的测试数据
        
//         info.setFileMeta(meta);
//         REQUIRE(info.checksumKnown());
//         REQUIRE(info.length() == 1024);
        
//         std::string consistentName = info.consistentName();
//         REQUIRE_FALSE(consistentName.empty());
//         REQUIRE(consistentName.find("root") != std::string::npos);
//     }
    
//     SECTION("BuilderWrapper完成功能测试") {
//         std::string gun = "docker.com/test";
//         TrustPinConfig trustpin;
//         auto cs = std::make_shared<CryptoService>();
        
//         auto builder = NewRepoBuilder(gun, cs, trustpin);
        
//         // 完成构建
//         auto result = builder->finish();
//         REQUIRE(result.ok());
        
//         auto [repo, invalidRepo] = result.value();
//         REQUIRE(repo != nullptr);
//         REQUIRE(invalidRepo != nullptr);
        
//         // 完成后应该拒绝进一步操作
//         std::vector<uint8_t> dummyContent = {0x7b, 0x7d}; // "{}"
//         auto loadError = builder->load(notary::RoleName::RootRole, dummyContent, 1, false);
//         REQUIRE(loadError.hasError());
//         REQUIRE(loadError.what().find("finished building") != std::string::npos);
//     }
    
//     SECTION("FinishedBuilder测试") {
//         FinishedBuilder finished;
        
//         // 所有操作都应该返回错误
//         std::vector<uint8_t> dummyContent = {0x7b, 0x7d}; // "{}"
        
//         auto loadError = finished.load(notary::RoleName::RootRole, dummyContent, 1, false);
//         REQUIRE(loadError.hasError());
        
//         auto updateError = finished.loadRootForUpdate(dummyContent, 1, true);
//         REQUIRE(updateError.hasError());
        
//         auto snapshotResult = finished.generateSnapshot();
//         REQUIRE_FALSE(snapshotResult.ok());
        
//         auto timestampResult = finished.generateTimestamp();
//         REQUIRE_FALSE(timestampResult.ok());
        
//         auto finishResult = finished.finish();
//         REQUIRE_FALSE(finishResult.ok());
        
//         // 信息方法应该返回默认值
//         REQUIRE_FALSE(finished.isLoaded(notary::RoleName::RootRole));
//         REQUIRE(finished.getLoadedVersion(notary::RoleName::RootRole) == 0);
        
//         auto info = finished.getConsistentInfo(notary::RoleName::RootRole);
//         REQUIRE(info.getRoleName() == notary::RoleName::RootRole);
//     }
// }

// TEST_CASE("Builder验证功能测试", "[builder][validation]") {
    
//     SECTION("无效角色验证") {
//         std::string gun = "docker.com/test";
//         TrustPinConfig trustpin;
//         auto cs = std::make_shared<CryptoService>();
        
//         auto builder = NewRepoBuilder(gun, cs, trustpin);
        
//         // 尝试加载无效内容应该失败
//         std::vector<uint8_t> invalidContent = {0x00, 0x01, 0x02}; // 无效JSON
        
//         // 注意：这个测试可能需要根据实际的loadRoot实现来调整
//         // 因为我们在实现中返回了"not implemented yet"错误
//         auto error = builder->load(notary::RoleName::RootRole, invalidContent, 1, false);
//         REQUIRE(error.hasError());
//     }
    
//     SECTION("引导新构建器") {
//         std::string gun = "docker.com/test";
//         TrustPinConfig trustpin;
//         auto cs = std::make_shared<CryptoService>();
        
//         auto builder = NewRepoBuilder(gun, cs, trustpin);
        
//         // 引导新的构建器
//         auto newBuilder = builder->bootstrapNewBuilder();
//         REQUIRE(newBuilder != nullptr);
//         REQUIRE_FALSE(newBuilder->isLoaded(notary::RoleName::RootRole));
        
//         // 用新的trust pin配置引导
//         TrustPinConfig newTrustPin;
//         newTrustPin.disableTOFU = true;
//         auto newBuilderWithPin = builder->bootstrapNewBuilderWithNewTrustpin(newTrustPin);
//         REQUIRE(newBuilderWithPin != nullptr);
//     }
// } 