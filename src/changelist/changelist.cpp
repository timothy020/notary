#include "notary/changelist/changelist.hpp"
#include "notary/utils/logger.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <uuid/uuid.h>
#include <iostream>
#include <set>

namespace notary {
namespace changelist {

using json = nlohmann::json;
namespace fs = std::filesystem;

// TUFChange序列化方法
std::vector<uint8_t> TUFChange::Serialize() const {
    json j;
    j["action"] = action_;
    j["scope"] = scope_;
    j["type"] = type_;
    j["path"] = path_;
    
    if (!content_.empty()) {
        // 将二进制内容转换为base64或直接存储为字符串
        std::string contentStr(content_.begin(), content_.end());
        j["content"] = contentStr;
    } else {
        j["content"] = nullptr;
    }
    
    std::string jsonStr = j.dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

// TUFRootData序列化方法
std::vector<uint8_t> TUFRootData::Serialize() const {
    json j;
    j["roleName"] = roleToString(RoleName);
    j["keys"] = json::array();
    
    for (const auto& key : Keys) {
        json keyJson;
        keyJson["id"] = key->ID();
        keyJson["algorithm"] = key->Algorithm();
        keyJson["public"] = key->Public();
        j["keys"].push_back(keyJson);
    }
    
    std::string jsonStr = j.dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

// FileChangeListIterator实现
class FileChangeListIterator : public ChangeIterator {
private:
    int index_;
    std::string dirname_;
    std::vector<fs::directory_entry> collection_;

public:
    FileChangeListIterator(const std::string& dirname, const std::vector<fs::directory_entry>& collection)
        : index_(0), dirname_(dirname), collection_(collection) {}

    std::shared_ptr<Change> Next() override {
        if (index_ >= static_cast<int>(collection_.size())) {
            return nullptr; // 越界
        }
        
        auto entry = collection_[index_];
        index_++;
        
        return unmarshalFile(dirname_, entry);
    }

    bool HasNext() const override {
        return index_ < static_cast<int>(collection_.size());
    }

private:
    // 从文件读取并反序列化TUFChange
    std::shared_ptr<TUFChange> unmarshalFile(const std::string& dirname, const fs::directory_entry& entry) {
        try {
            std::ifstream file(entry.path());
            if (!file.is_open()) {
                utils::GetLogger().Error("Failed to open file", utils::LogContext().With("path", entry.path()));
                return nullptr;
            }

            json j;
            file >> j;

            std::string action = j.value("action", "");
            std::string scope = j.value("scope", "");
            std::string type = j.value("type", "");
            std::string path = j.value("path", "");
            
            std::vector<uint8_t> content;
            if (j.contains("content") && !j["content"].is_null()) {
                if (j["content"].is_string()) {
                    std::string contentStr = j["content"];
                    content = std::vector<uint8_t>(contentStr.begin(), contentStr.end());
                }
            }

            return std::make_shared<TUFChange>(action, scope, type, path, content);
        } catch (const std::exception& e) {
            utils::GetLogger().Error("Error unmarshaling file", utils::LogContext().With("error", e.what()));
            return nullptr;
        }
    }
};

// FileChangelist实现
FileChangelist::FileChangelist(const std::string& dir) : dir_(dir) {
    try {
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to create changelist directory: " << e.what() << std::endl;
    }
}

// 获取目录中的文件名，过滤掉子目录 (对应Go的getFileNames)
std::vector<fs::directory_entry> getFileNames(const std::string& dirName) {
    std::vector<fs::directory_entry> fileInfos;
    
    try {
        if (!fs::exists(dirName)) {
            return fileInfos;
        }

        for (const auto& entry : fs::directory_iterator(dirName)) {
            if (entry.is_regular_file()) {
                fileInfos.push_back(entry);
            }
        }

        // 按文件名排序 (对应Go的sort.Sort(fileChanges(fileInfos)))
        std::sort(fileInfos.begin(), fileInfos.end(),
                 [](const fs::directory_entry& a, const fs::directory_entry& b) {
                     return a.path().filename().string() < b.path().filename().string();
                 });
    } catch (const std::exception& e) {
        utils::GetLogger().Error("Error reading directory", utils::LogContext().With("error", e.what()));
    }

    return fileInfos;
}

// 从文件读取并转换为TUFChange (对应Go的unmarshalFile)
std::shared_ptr<TUFChange> unmarshalFile(const std::string& dirname, const fs::directory_entry& entry) {
    try {
        std::ifstream file(entry.path());
        if (!file.is_open()) {
            return nullptr;
        }

        json j;
        file >> j;

        std::string action = j.value("action", "");
        std::string scope = j.value("scope", "");
        std::string type = j.value("type", "");
        std::string path = j.value("path", "");
        
        std::vector<uint8_t> content;
        if (j.contains("content") && !j["content"].is_null()) {
            if (j["content"].is_string()) {
                std::string contentStr = j["content"];
                content = std::vector<uint8_t>(contentStr.begin(), contentStr.end());
            }
        }

        return std::make_shared<TUFChange>(action, scope, type, path, content);
    } catch (const std::exception& e) {
        utils::GetLogger().Error("Error unmarshaling file", utils::LogContext().With("error", e.what()));
        return nullptr;
    }
}

std::vector<std::shared_ptr<Change>> FileChangelist::List() const {
    std::vector<std::shared_ptr<Change>> changes;
    auto fileInfos = getFileNames(dir_);
    
    for (const auto& entry : fileInfos) {
        auto change = unmarshalFile(dir_, entry);
        if (change) {
            changes.push_back(change);
        }
    }
    
    return changes;
}

Error FileChangelist::Add(const std::shared_ptr<Change>& change) {
    try {
        // 序列化变更为JSON
        auto changeBytes = change->Serialize();

        // 生成唯一文件名 (对应Go的fmt.Sprintf("%020d_%s.change", time.Now().UnixNano(), uuid.Generate()))
        auto now = std::chrono::system_clock::now();
        auto nowNano = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();
        
        // 生成UUID
        uuid_t uuid;
        uuid_generate(uuid);
        char uuidStr[37];
        uuid_unparse(uuid, uuidStr);
        
        std::stringstream ss;
        ss << std::setw(20) << std::setfill('0') << nowNano << "_" << uuidStr << ".change";
        std::string filename = ss.str();
        
        // 写入文件
        fs::path filePath = fs::path(dir_) / filename;
        std::ofstream file(filePath);
        if (!file.is_open()) {
            return Error("Failed to create change file: " + filePath.string());
        }
        
        file.write(reinterpret_cast<const char*>(changeBytes.data()), changeBytes.size());
        file.close();
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add change: ") + e.what());
    }
}

Error FileChangelist::Remove(const std::vector<int>& idxs) {
    try {
        auto fileInfos = getFileNames(dir_);
        
        // 创建要删除的索引集合
        std::set<int> removeSet(idxs.begin(), idxs.end());
        
        for (int i = 0; i < static_cast<int>(fileInfos.size()); ++i) {
            if (removeSet.count(i)) {
                try {
                    fs::remove(fileInfos[i].path());
                } catch (const std::exception& e) {
                    std::cerr << "Could not remove change " << i << ": " << e.what() << std::endl;
                }
            }
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to remove changes: ") + e.what());
    }
}

Error FileChangelist::Clear(const std::string& archive) {
    try {
        // N.B. archiving not currently implemented (对应Go注释)
        if (!fs::exists(dir_)) {
            return Error(); // 目录不存在，认为已清空
        }

        // 删除目录中的所有文件
        for (const auto& entry : fs::directory_iterator(dir_)) {
            if (entry.is_regular_file()) {
                fs::remove(entry.path());
            }
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to clear changelist: ") + e.what());
    }
}

Error FileChangelist::Close() {
    // Nothing to do here (对应Go的注释)
    return Error(); // 成功
}

std::unique_ptr<ChangeIterator> FileChangelist::NewIterator() {
    auto fileInfos = getFileNames(dir_);
    return std::make_unique<FileChangeListIterator>(dir_, fileInfos);
}

} // namespace changelist
} // namespace notary
