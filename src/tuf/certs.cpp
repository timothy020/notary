#include "notary/tuf/certs.hpp"
#include "notary/utils/logger.hpp"
#include "notary/crypto/verify.hpp"
#include "notary/utils/x509.hpp"
#include "notary/tuf/trustpinning.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace notary {
namespace tuf {

// 通配符常量 - 对应Go版本的wildcard
const std::string wildcard = "*";

// prettyFormatCertIDs formats certificate IDs for logging
// 对应Go版本的prettyFormatCertIDs函数
std::string prettyFormatCertIDs(const std::map<std::string, std::shared_ptr<utils::Certificate>>& certs) {
    std::vector<std::string> ids;
    for (const auto& pair : certs) {
        ids.push_back(pair.first);
    }
    
    std::string result;
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i > 0) result += ", ";
        result += ids[i];
    }
    return result;
}

// parseAllCerts returns two maps, one with all of the leafCertificates and one
// with all the intermediate certificates found in signedRoot
// 对应Go版本的trustpinning.parseAllCerts函数
std::pair<std::map<std::string, std::shared_ptr<utils::Certificate>>, 
          std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>>
parseAllCerts(std::shared_ptr<SignedRoot> signedRoot) {
    // 定义返回类型别名以提高可读性
    using LeafCertsMap = std::map<std::string, std::shared_ptr<utils::Certificate>>;
    using IntCertsMap = std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>;
    
    if (!signedRoot) {
        utils::GetLogger().Debug("parseAllCerts: signedRoot is null");
        return std::make_pair(LeafCertsMap{}, IntCertsMap{});
    }
    
    LeafCertsMap leafCerts;
    IntCertsMap intCerts;
    
    // 对应Go版本的 rootRoles, ok := signedRoot.Signed.Roles[data.CanonicalRootRole]
    auto rootRoleIt = signedRoot->Signed.Roles.find(RoleName::RootRole);
    if (rootRoleIt == signedRoot->Signed.Roles.end()) {
        utils::GetLogger().Debug("parseAllCerts: tried to parse certificates from invalid root signed data");
        return std::make_pair(LeafCertsMap{}, IntCertsMap{});
    }
    
    const auto& rootRole = rootRoleIt->second;
    
    // 获取root角色的所有密钥（对应Go版本的rootRoles.KeyIDs）
    const auto& roleKeys = rootRole.Keys();
    
    utils::GetLogger().Debug("parseAllCerts: found " + std::to_string(roleKeys.size()) + " root keys");
    
    // 对应Go版本的 for _, keyID := range rootRoles.KeyIDs
    for (const auto& key : roleKeys) {
        if (!key) {
            utils::GetLogger().Debug("parseAllCerts: encountered null key, skipping");
            continue;
        }
        
        std::string keyID = key->ID();
        
        try {
            // 对应Go版本的 decodedCerts, err := utils.LoadCertBundleFromPEM(key.Public())
            std::vector<uint8_t> keyPublicData = key->Public();
            auto decodedCerts = utils::LoadCertBundleFromPEM(keyPublicData);
            
            // 对应Go版本的 leafCertList := utils.GetLeafCerts(decodedCerts)
            auto leafCertList = utils::GetLeafCerts(decodedCerts);
            
            // 对应Go版本的 if len(leafCertList) != 1
            if (leafCertList.size() != 1) {
                utils::GetLogger().Debug("parseAllCerts: invalid chain due to leaf certificate missing or too many leaf certificates for keyID: " + keyID);
                continue;
            }
            
            // 对应Go版本的 if decodedCerts[0].IsCA
            if (decodedCerts.size() > 0 && decodedCerts[0]->IsCA()) {
                utils::GetLogger().Debug("parseAllCerts: invalid chain due to leaf certificate not being first certificate for keyID: " + keyID);
                continue;
            }
            
            // 对应Go版本的 leafCert := leafCertList[0]
            auto leafCert = leafCertList[0];
            
            // 对应Go版本的 leafCerts[key.ID()] = leafCert
            leafCerts[key->ID()] = leafCert;
            
            // 对应Go版本的 intermediateCerts := utils.GetIntermediateCerts(decodedCerts)
            auto intermediateCerts = utils::GetIntermediateCerts(decodedCerts);
            
            // 对应Go版本的 intCerts[key.ID()] = intermediateCerts
            intCerts[key->ID()] = intermediateCerts;
            
            utils::GetLogger().Debug("parseAllCerts: successfully processed keyID: " + keyID + 
                                   " with " + std::to_string(intermediateCerts.size()) + " intermediate certificates");
            
        } catch (const std::exception& e) {
            // 对应Go版本的错误处理
            utils::GetLogger().Debug("parseAllCerts: error while parsing root certificate with keyID: " + keyID + ", " + e.what());
            continue;
        }
    }
    
    utils::GetLogger().Debug("parseAllCerts: found " + std::to_string(leafCerts.size()) + 
                           " leaf certificates and intermediate certificates for " + 
                           std::to_string(intCerts.size()) + " keys");
    
    return std::make_pair(leafCerts, intCerts);
}

// MatchCNToGun checks that the common name in a cert is valid for the given gun.
// This allows wildcards as suffixes, e.g. `namespace/*`
// 对应Go版本的trustpinning.MatchCNToGun函数
bool MatchCNToGun(const std::string& commonName, const std::string& gun) {
    if (commonName.length() >= wildcard.length() && 
        commonName.substr(commonName.length() - wildcard.length()) == wildcard) {
        
        // 对应Go版本的 prefix := strings.TrimRight(commonName, wildcard)
        std::string prefix = commonName.substr(0, commonName.length() - wildcard.length());
        
        utils::GetLogger().Debug("checking gun " + gun + " against wildcard prefix " + prefix);
        
        // 对应Go版本的 return strings.HasPrefix(gun.String(), prefix)
        return gun.length() >= prefix.length() && 
               gun.substr(0, prefix.length()) == prefix;
    }
    
    return commonName == gun;
}

// validRootLeafCerts returns a list of possibly (if checkExpiry is true) non-expired, non-sha1 certificates
// found in root whose Common-Names match the provided GUN. Note that this
// "validity" alone does not imply any measure of trust.
// 对应Go版本的trustpinning.validRootLeafCerts函数
std::pair<std::map<std::string, std::shared_ptr<utils::Certificate>>, Error>
validRootLeafCerts(const std::map<std::string, std::shared_ptr<utils::Certificate>>& allLeafCerts, 
                   const std::string& gun, 
                   bool checkExpiry) {
    
    // 对应Go版本的 validLeafCerts := make(map[string]*x509.Certificate)
    std::map<std::string, std::shared_ptr<utils::Certificate>> validLeafCerts;
    
    // 对应Go版本的 for id, cert := range allLeafCerts
    for (const auto& pair : allLeafCerts) {
        const std::string& id = pair.first;
        const auto& cert = pair.second;
        
        if (!cert) {
            utils::GetLogger().Debug("validRootLeafCerts: skipping null certificate for id: " + id);
            continue;
        }
        
        // 对应Go版本的 if !MatchCNToGun(cert.Subject.CommonName, gun)
        std::string commonName = cert->GetCommonName();
        if (!MatchCNToGun(commonName, gun)) {
            utils::GetLogger().Debug("error leaf certificate CN: " + commonName + 
                                   " doesn't match the given GUN: " + gun);
            continue;
        }
        
        // 对应Go版本的 if err := utils.ValidateCertificate(cert, checkExpiry); err != nil
        Error validationError = utils::ValidateCertificate(*cert, checkExpiry);
        if (!validationError.ok()) {
            utils::GetLogger().Debug(id + " is invalid: " + validationError.getMessage());
            continue;
        }
        
        // 对应Go版本的 validLeafCerts[id] = cert
        validLeafCerts[id] = cert;
    }
    
    // 对应Go版本的 if len(validLeafCerts) < 1
    if (validLeafCerts.empty()) {
        utils::GetLogger().Debug("didn't find any valid leaf certificates for " + gun);
        return std::make_pair(validLeafCerts, 
                             Error("no valid leaf certificates found in any of the root keys"));
    }
    
    // 对应Go版本的日志输出
    utils::GetLogger().Debug("found " + std::to_string(validLeafCerts.size()) + 
                           " valid leaf certificates for " + gun + ": " + 
                           prettyFormatCertIDs(validLeafCerts));
    
    return std::make_pair(validLeafCerts, Error()); // 成功时返回空Error
}

// validRootIntCerts filters the passed in structure of intermediate certificates to only include non-expired, non-sha1 certificates
// Note that this "validity" alone does not imply any measure of trust.
// 对应Go版本的trustpinning.validRootIntCerts函数
std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>
validRootIntCerts(const std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>>& allIntCerts) {
    
    // 对应Go版本的 validIntCerts := make(map[string][]*x509.Certificate)
    std::map<std::string, std::vector<std::shared_ptr<utils::Certificate>>> validIntCerts;
    
    // 对应Go版本的 for leafID, intCertList := range allIntCerts
    for (const auto& pair : allIntCerts) {
        const std::string& leafID = pair.first;
        const auto& intCertList = pair.second;
        
        // 对应Go版本的 for _, intCert := range intCertList
        for (const auto& intCert : intCertList) {
            if (!intCert) {
                utils::GetLogger().Debug("validRootIntCerts: skipping null intermediate certificate for leafID: " + leafID);
                continue;
            }
            
            // 对应Go版本的 if err := utils.ValidateCertificate(intCert, true); err != nil
            Error validationError = utils::ValidateCertificate(*intCert, true);
            if (!validationError.ok()) {
                utils::GetLogger().Debug("Invalid intermediate certificate for leafID " + leafID + 
                                       ": " + validationError.getMessage());
                continue;
            }
            
            // 对应Go版本的 validIntCerts[leafID] = append(validIntCerts[leafID], intCert)
            validIntCerts[leafID].push_back(intCert);
        }
    }
    
    utils::GetLogger().Debug("validRootIntCerts: processed " + std::to_string(allIntCerts.size()) + 
                           " leaf IDs, found valid intermediate certificates for " + 
                           std::to_string(validIntCerts.size()) + " leaf IDs");
    
    return validIntCerts;
}

// ValidateRoot receives a new root, validates its correctness and attempts to
// do root key rotation if needed - 对应Go版本的ValidateRoot函数
Result<std::shared_ptr<SignedRoot>> ValidateRoot(
    std::shared_ptr<SignedRoot> prevRoot,
    std::shared_ptr<tuf::Signed> root,
    const std::string& gun,
    const TrustPinConfig& trustPinning
) {
    utils::GetLogger().Debug("entered ValidateRoot with dns: " + gun);
    
    // 第一步：从Signed创建SignedRoot（对应Go版本的data.RootFromSigned(root)）
    auto signedRootResult = RootFromSigned(root);
    if (!signedRootResult.ok()) {
        utils::GetLogger().Error("ValidateRoot: Failed to create SignedRoot from Signed: " + signedRootResult.error().getMessage());
        return signedRootResult;
    }
    auto signedRoot = signedRootResult.value();
    
    // 第二步：构建root角色（对应Go版本的signedRoot.BuildBaseRole(data.CanonicalRootRole)）
    auto rootRoleResult = signedRoot->BuildBaseRole(RoleName::RootRole);
    if (!rootRoleResult.ok()) {
        utils::GetLogger().Error("ValidateRoot: Failed to build root role: " + rootRoleResult.error().getMessage());
        return Result<std::shared_ptr<SignedRoot>>(rootRoleResult.error());
    }
    auto rootRole = rootRoleResult.value();
    
    // 第三步：解析所有证书（对应Go版本的parseAllCerts(signedRoot)）
    auto [allLeafCerts, allIntCerts] = parseAllCerts(signedRoot);
    
    // 第四步：验证根叶子证书（对应Go版本的validRootLeafCerts(allLeafCerts, gun, true)）
    auto [certsFromRoot, certError] = validRootLeafCerts(allLeafCerts, gun, true);
    auto validIntCerts = validRootIntCerts(allIntCerts);
    
    if (!certError.ok()) {
        utils::GetLogger().Debug("error retrieving valid leaf certificates for: " + gun + ", " + certError.getMessage());
        throw ErrValidationFail("unable to retrieve valid leaf certificates");
    }
    
    utils::GetLogger().Debug("found " + std::to_string(allLeafCerts.size()) + " leaf certs, of which " + 
                           std::to_string(certsFromRoot.size()) + " are valid leaf certs for " + gun);
    
    // 第五步：如果有之前的root，用它验证新root（对应Go版本的havePrevRoot逻辑）
    bool havePrevRoot = (prevRoot != nullptr);
    if (havePrevRoot) {
        utils::GetLogger().Debug("ValidateRoot: Validating with previous root");
        
        // 从之前的root检索可信证书（对应Go版本的parseAllCerts(prevRoot)）
        // 注意：这里不验证过期时间，因为原本可信的root可能包含过期证书
        auto [allTrustedLeafCerts, allTrustedIntCerts] = parseAllCerts(prevRoot);
        auto [trustedLeafCerts, trustedCertError] = validRootLeafCerts(allTrustedLeafCerts, gun, false);
        
        if (!trustedCertError.ok()) {
            throw ErrValidationFail("could not retrieve trusted certs from previous root role data");
        }
        
        utils::GetLogger().Debug("found " + std::to_string(trustedLeafCerts.size()) + 
                               " valid root leaf certificates for " + gun + ": " + 
                               prettyFormatCertIDs(trustedLeafCerts));
        
        // 提取之前root的threshold用于签名验证（对应Go版本的prevRootRoleData.Threshold）
        auto prevRootRoles = prevRoot->Signed.Roles;
        auto prevRootRoleIt = prevRootRoles.find(RoleName::RootRole);
        if (prevRootRoleIt == prevRootRoles.end()) {
            throw ErrValidationFail("could not retrieve previous root role data");
        }
        
        // 使用之前root中找到的证书来验证签名（对应Go版本的signed.VerifySignatures）
        auto trustedKeys = utils::CertsToKeys(trustedLeafCerts, allTrustedIntCerts);
        BaseRole prevRootRole(RoleName::RootRole, prevRootRoleIt->second.Threshold(), {});
        
        // 将map转换为vector用于BaseRole
        std::vector<std::shared_ptr<crypto::PublicKey>> keyVector;
        for (const auto& [keyId, key] : trustedKeys) {
            keyVector.push_back(key);
        }
        prevRootRole.SetKeys(keyVector);
        
        // 修复：使用完整的namespace路径
        auto verifyError = notary::crypto::VerifySignatures(*root, prevRootRole);
        if (!verifyError.ok()) {
            utils::GetLogger().Debug("failed to verify TUF data for: " + gun + ", " + verifyError.getMessage());
            throw ErrRootRotationFail("failed to validate data with current trusted certificates");
        }
        
        // 清除从VerifySignatures可能收到的IsValid标记（对应Go版本的清除IsValid）
        for (auto& sig : root->Signatures) {
            sig.IsValid = false;
        }
    }
    
    // 第六步：无论是否有之前的root，都要确认新root符合trust pinning（对应Go版本的trust pinning检查）
    utils::GetLogger().Debug("checking root against trust_pinning config for " + gun);
    auto trustPinCheckFunc = NewTrustPinChecker(trustPinning, gun, !havePrevRoot);
    
    // 对每个证书进行trust-pinning检查（对应Go版本的trust pinning循环）
    std::map<std::string, std::shared_ptr<utils::Certificate>> validPinnedCerts;
    for (const auto& [id, cert] : certsFromRoot) {
        utils::GetLogger().Debug("checking trust-pinning for cert: " + id);
        
        // 获取该证书对应的中间证书列表
        std::vector<std::shared_ptr<utils::Certificate>> intCertsForId;
        auto intCertIt = validIntCerts.find(id);
        if (intCertIt != validIntCerts.end()) {
            intCertsForId = intCertIt->second;
        }
        
        // 执行trust-pinning检查（对应Go版本的trustPinCheckFunc调用）
        if (!trustPinCheckFunc(cert, intCertsForId)) {
            utils::GetLogger().Debug("trust-pinning check failed for cert: " + id);
            continue;
        }
        validPinnedCerts[id] = cert;
    }
    
    if (validPinnedCerts.empty()) {
        throw ErrValidationFail("unable to match any certificates to trust_pinning config");
    }
    certsFromRoot = validPinnedCerts;
    
    // 第七步：验证新root的完整性（是否有有效签名）（对应Go版本的最终签名验证）
    // 注意：certsFromRoot只有在我们有此GUN的之前证书数据或启用TOFUS时才保证不变
    // 如果我们尝试固定某个证书或CA，certsFromRoot可能会相应地被修剪
    auto finalKeys = utils::CertsToKeys(certsFromRoot, validIntCerts);
    
    // 将map转换为vector用于BaseRole
    std::vector<std::shared_ptr<crypto::PublicKey>> finalKeyVector;
    for (const auto& [keyId, key] : finalKeys) {
        finalKeyVector.push_back(key);
    }
    
    BaseRole finalRootRole(RoleName::RootRole, rootRole.Threshold(), finalKeyVector);
    // 修复：使用完整的namespace路径
    auto finalVerifyError = notary::crypto::VerifySignatures(*root, finalRootRole);
    if (!finalVerifyError.ok()) {
        utils::GetLogger().Debug("failed to verify TUF data for: " + gun + ", " + finalVerifyError.getMessage());
        throw ErrValidationFail("failed to validate integrity of roots");
    }
    
    utils::GetLogger().Debug("root validation succeeded for " + gun);
    
    // 第八步：调用RootFromSigned确保我们获取到VerifySignatures的IsValid标记（对应Go版本的最后调用）
    return RootFromSigned(root);
}

}
}
