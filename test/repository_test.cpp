#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "notary/repository.hpp"
#include <sys/stat.h>
#include <unistd.h>

using namespace notary;

bool exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

void create_directories(const std::string& path) {
    std::string cmd = "mkdir -p " + path;
    system(cmd.c_str());
}

void remove_all(const std::string& path) {
    std::string cmd = "rm -rf " + path;
    system(cmd.c_str());
}

TEST_CASE("Repository Initialization", "[repository]") {
    // 创建临时目录
    std::string tempDir = "/tmp/notary_test";
    create_directories(tempDir);
    
    SECTION("Initialize with no root key") {
        Repository repo(tempDir, "http://localhost:4443");
        auto err = repo.Initialize({});
        REQUIRE(err.ok());
        
        // 验证元数据文件是否创建
        std::string metadataDir = tempDir + "/tuf/metadata";
        REQUIRE(exists(metadataDir + "/root.json"));
        REQUIRE(exists(metadataDir + "/targets.json"));
        REQUIRE(exists(metadataDir + "/snapshot.json"));
    }
    
    SECTION("Initialize with invalid root key") {
        Repository repo(tempDir, "http://localhost:4443");
        auto err = repo.Initialize({"invalid_key_id"});
        REQUIRE_FALSE(err.ok());
        REQUIRE(err.what() == "Root key not found: invalid_key_id");
    }
    
    // 清理
    remove_all(tempDir);
} 