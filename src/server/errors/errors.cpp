#include "notary/server/errors.hpp"

namespace notary {
namespace server {

const Error Error::Success(0, "");
const Error Error::ErrUnknown(1, "未知错误");
const Error Error::ErrMetadataNotFound(2, "元数据未找到");
const Error Error::ErrMalformedUpload(3, "畸形的上传请求");
const Error Error::ErrInvalidRole(4, "无效的角色");
const Error Error::ErrNoStorage(5, "存储服务不可用");
const Error Error::ErrNoFilename(6, "未指定文件名");
const Error Error::ErrMalformedJSON(7, "畸形的JSON数据");
const Error Error::ErrInvalidUpdate(8, "无效的更新请求");
const Error Error::ErrOldVersion(9, "版本过旧");
const Error Error::ErrNoKeyAlgorithm(10, "未指定密钥算法");
const Error Error::ErrNoCryptoService(11, "加密服务不可用");
const Error Error::ErrUpdating(12, "更新过程中出错");
const Error Error::ErrInvalidGUN(13, "无效的GUN");

} // namespace server
} // namespace notary 