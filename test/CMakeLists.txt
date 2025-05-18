# 启用测试
enable_testing()

# 添加Catch2依赖
find_package(Catch2 3 REQUIRED)

# 收集所有测试源文件
file(GLOB TEST_SOURCES "*.cpp")

# 创建测试可执行文件
add_executable(notary_tests ${TEST_SOURCES})

# 设置包含目录
target_include_directories(notary_tests
    PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# 链接依赖库
target_link_libraries(notary_tests
    PRIVATE
    notary_lib
    Catch2::Catch2WithMain
)

# 添加测试
add_test(NAME notary_tests COMMAND notary_tests) 