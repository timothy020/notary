#include "notary/server/errors.hpp"

namespace notary {
namespace server {

const Error Error::Success(0, "");
const Error Error::ErrMetadataNotFound(1, "元数据未找到");
const Error Error::ErrMalformedUpload(2, "畸形的上传请求");
const Error Error::ErrInvalidRole(3, "无效的角色");
const Error Error::ErrNoStorage(4, "存储服务不可用");
const Error Error::ErrNoFilename(5, "未指定文件名");
const Error Error::ErrMalformedJSON(6, "畸形的JSON数据");
const Error Error::ErrInvalidUpdate(7, "无效的更新请求");
const Error Error::ErrOldVersion(8, "版本过旧");
const Error Error::ErrNoKeyAlgorithm(9, "未指定密钥算法");
const Error Error::ErrNoCryptoService(10, "加密服务不可用");
const Error Error::ErrUpdating(11, "更新过程中出错");
const Error Error::ErrInvalidGUN(12, "无效的GUN");
const Error Error::ErrUnknown(13, "未知错误");

} // namespace server
} // namespace notary 