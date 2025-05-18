# 收集所有源文件
file(GLOB_RECURSE SOURCES 
    "*.cpp"
    "cmd/*.cpp"
    "crypto/*.cpp"
    "repository/*.cpp"
    "storage/*.cpp"
    "config/*.cpp"
)

# 创建库
add_library(notary_lib STATIC ${SOURCES})

# 设置包含目录
target_include_directories(notary_lib
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${UUID_INCLUDE_DIRS}
)

# 链接依赖库
target_link_libraries(notary_lib
    PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    ${UUID_LIBRARIES}
) 