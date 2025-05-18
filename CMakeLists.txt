cmake_minimum_required(VERSION 3.15)
project(notary_cpp VERSION 0.1.0)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# 启用测试
enable_testing() 

# 添加OpenSSL依赖
find_package(OpenSSL REQUIRED)

# 添加uuid库依赖
find_package(PkgConfig REQUIRED)
pkg_check_modules(UUID REQUIRED uuid)

# 添加libcurl依赖
find_package(CURL REQUIRED)

# 添加CLI11和nlohmann-json依赖
find_package(CLI11 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Catch2 CONFIG REQUIRED) 

# 添加cpp-httplib依赖 (header-only库)
include(FetchContent)
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.11.2
)
FetchContent_MakeAvailable(httplib)

# 获取httplib源目录
message(STATUS "httplib source dir: ${httplib_SOURCE_DIR}")

# 添加子目录
add_subdirectory(src)
add_subdirectory(test)

# 设置可执行文件输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# 添加客户端可执行文件
add_executable(notary src/main.cpp)

# 添加服务器可执行文件
add_executable(notary-server src/server_main.cpp
    src/server/server.cpp
    src/server/handlers/default.cpp
    src/server/errors/errors.cpp
)

# 设置客户端包含目录和链接库
target_include_directories(notary
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${UUID_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

target_link_libraries(notary
    PRIVATE
    notary_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    ${UUID_LIBRARIES}
    ${CURL_LIBRARIES}
) 

# 设置服务器包含目录和链接库
target_include_directories(notary-server
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${httplib_SOURCE_DIR}
    ${UUID_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

target_link_libraries(notary-server
    PRIVATE
    notary_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    ${UUID_LIBRARIES}
    ${CURL_LIBRARIES}
) 