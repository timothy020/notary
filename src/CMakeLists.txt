# 收集所有源文件
file(GLOB_RECURSE SOURCES 
    "*.cpp"
    "cmd/*.cpp"
    "crypto/*.cpp"
    "client/*.cpp"
    "storage/*.cpp"
    "config/*.cpp"
    "utils/*.cpp"
    "tuf/*.cpp"
    "changelist/*.cpp"
    "passRetriever/*.cpp"
)

# 创建库
add_library(notary_lib 
    crypto/crypto_service.cpp
    crypto/keys.cpp
    crypto/sign.cpp
    crypto/verify.cpp
    crypto/verifiers.cpp
    crypto/certificate.cpp
    main.cpp
    client/repository.cpp
    client/tufclient.cpp
    client/delegation.cpp
    storage/httpstore.cpp
    storage/keystore.cpp
    storage/filestore.cpp
    storage/memorystore.cpp
    storage/offlinestore.cpp
    server/server.cpp
    server/handlers/default.cpp
    server/handlers/validation.cpp
    server/errors/errors.cpp
    server/storage/file_storage.cpp
    utils/logger.cpp
    utils/tools.cpp
    utils/helpers.cpp
    utils/x509.cpp
    changelist/changelist.cpp
    passRetriever/passRetriever.cpp
    types.cpp
    server_main.cpp
    tuf/repo.cpp
    tuf/builder.cpp
    tuf/trustpinning.cpp
    tuf/certs.cpp
)

# 设置包含目录
target_include_directories(notary_lib
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${httplib_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${UUID_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

# 链接依赖库
target_link_libraries(notary_lib
    PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    ${UUID_LIBRARIES}
    ${CURL_LIBRARIES}
) 