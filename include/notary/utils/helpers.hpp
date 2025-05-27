#pragma once

#include <vector>
#include <memory>
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/changelist/changelist.hpp"

namespace notary {
namespace utils {
    std::chrono::system_clock::time_point getDefaultExpiry(RoleName role);
    std::vector<uint8_t> serializeCanonicalRole(std::shared_ptr<tuf::Repo> tufRepo, RoleName role, const std::vector<std::shared_ptr<crypto::PublicKey>>& extraSigningKeys);
     
    // applyChangelist相关函数声明 (对应Go的applyChangelist函数族)
    Error applyChangelist(std::shared_ptr<tuf::Repo> repo, 
                         std::shared_ptr<tuf::Repo> invalid, 
                         std::shared_ptr<changelist::Changelist> cl);
    
    Error applyTargetsChange(std::shared_ptr<tuf::Repo> repo, 
                            std::shared_ptr<tuf::Repo> invalid, 
                            std::shared_ptr<changelist::Change> change);
    
    Error changeTargetMeta(std::shared_ptr<tuf::Repo> repo, 
                          std::shared_ptr<changelist::Change> change);
    
    Error changeTargetsDelegation(std::shared_ptr<tuf::Repo> repo, 
                                 std::shared_ptr<changelist::Change> change);
    
    Error applyRootChange(std::shared_ptr<tuf::Repo> repo, 
                         std::shared_ptr<changelist::Change> change);
    
    Error applyRootRoleChange(std::shared_ptr<tuf::Repo> repo, 
                             std::shared_ptr<changelist::Change> change);
    
    Error witnessTargets(std::shared_ptr<tuf::Repo> repo, 
                        std::shared_ptr<tuf::Repo> invalid, 
                        RoleName scope);

}
}