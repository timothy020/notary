#pragma once

#include <string>
#include <utility>

namespace notary {
namespace server {

class Error {
public:
    Error() : code_(0), detail_("") {}
    Error(int code, std::string detail) : code_(code), detail_(std::move(detail)) {}

    int Code() const { return code_; }
    const std::string& Detail() const { return detail_; }

    Error WithDetail(const std::string& detail) const {
        return Error(code_, detail);
    }

    int HTTPStatusCode() const {
        switch (code_) {
            case 0: // NoError
                return 200; // OK
            case 1: // ErrMetadataNotFound
            case 5: // ErrNoFilename
                return 404; // Not Found
            case 2: // ErrMalformedUpload
            case 3: // ErrInvalidRole
            case 6: // ErrMalformedJSON
            case 7: // ErrInvalidUpdate
            case 8: // ErrOldVersion
            case 12: // ErrInvalidGUN
                return 400; // Bad Request
            case 4: // ErrNoStorage
            case 10: // ErrNoCryptoService
            case 9: // ErrNoKeyAlgorithm
            case 11: // ErrUpdating
            default:
                return 500; // Internal Server Error
        }
    }

    // 静态错误定义
    static const Error Success;
    static const Error ErrUnknown;
    static const Error ErrMetadataNotFound;
    static const Error ErrMalformedUpload;
    static const Error ErrInvalidRole;
    static const Error ErrNoStorage;
    static const Error ErrNoFilename;
    static const Error ErrMalformedJSON;
    static const Error ErrInvalidUpdate;
    static const Error ErrOldVersion;
    static const Error ErrNoKeyAlgorithm;
    static const Error ErrNoCryptoService;
    static const Error ErrUpdating;
    static const Error ErrInvalidGUN;

private:
    int code_;
    std::string detail_;
};

} // namespace server
} // namespace notary 