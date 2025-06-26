#pragma once
#include <string>
#include "notary/types.hpp"

namespace notary {
namespace server {

struct MetaUpdate {
    std::string role;
    std::string roleName;
    int version;
    std::string data;
};

}
}
