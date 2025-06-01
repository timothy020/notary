#pragma once

#include "notary/server/server.hpp"
#include "notary/server/types.hpp"
#include "notary/tuf/builder.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/crypto/crypto_service.hpp"
#include <string>
#include <vector>
#include <map>

namespace notary {
namespace server {
namespace handlers {

// 主要验证函数
std::vector<MetaUpdate> validateUpdate(crypto::CryptoService* cryptoService, const std::string& gun, std::vector<MetaUpdate> updates, StorageService* store);

// 辅助函数声明
std::vector<MetaUpdate> loadAndValidateTargets(const std::string& gun, tuf::RepoBuilder* builder, const std::map<RoleName, MetaUpdate>& roles, StorageService* store);
MetaUpdate generateSnapshot(const std::string& gun, tuf::RepoBuilder* builder, StorageService* store);
MetaUpdate generateTimestamp(const std::string& gun, tuf::RepoBuilder* builder, StorageService* store);
void loadFromStore(const std::string& gun, RoleName roleName, tuf::RepoBuilder* builder, StorageService* store);

} // namespace handlers
} // namespace server
} // namespace notary