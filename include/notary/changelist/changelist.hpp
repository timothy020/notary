#pragma once

#include <string>
#include <vector>
#include <memory>
#include "notary/types.hpp"
#include "notary/crypto/keys.hpp"

namespace notary {
namespace changelist {

// 动作常量 (对应Go的ActionCreate, ActionUpdate, ActionDelete)
const std::string ActionCreate = "create";
const std::string ActionUpdate = "update";
const std::string ActionDelete = "delete";

// 作用域常量
const std::string ScopeRoot = "root";
const std::string ScopeTargets = "targets";

// 类型常量
const std::string TypeBaseRole = "role";
const std::string TypeTargetsTarget = "target";
const std::string TypeTargetsDelegation = "delegation";
const std::string TypeWitness = "witness";

// Change接口 - TUF变更的基类
class Change {
public:
    virtual ~Change() = default;
    
    // "create", "update", 或 "delete"
    virtual std::string Action() const = 0;
    
    // 变更应该在哪里进行
    // 对于TUF，这将是角色名
    virtual std::string Scope() const = 0;
    
    // 受影响的内容类型
    // 对于TUF，这将是"target"或"delegation"
    // 如果类型是"delegation"，Scope将用于确定是否更新root角色或target委托
    virtual std::string Type() const = 0;
    
    // 指示角色内受变更影响的条目路径
    // 对于targets，这只是target的路径
    // 对于delegations，这是委托的角色名
    virtual std::string Path() const = 0;
    
    // 序列化的内容，changelist的解释器可以使用它来应用变更
    // 对于TUF，这将是需要插入或合并的序列化JSON
    // 在"delete"动作的情况下，它将为空
    virtual const std::vector<uint8_t>& Content() const = 0;

    // 序列化当前变更为json
    virtual std::vector<uint8_t> Serialize() const = 0;
};

// ChangeIterator接口 - 用于遍历TUF Change项集合
class ChangeIterator {
public:
    virtual ~ChangeIterator() = default;
    
    virtual std::shared_ptr<Change> Next() = 0;
    virtual bool HasNext() const = 0;
};

// Changelist接口 - 所有TUF变更列表的接口
class Changelist {
public:
    virtual ~Changelist() = default;
    
    // List返回当前存储的有序变更列表
    virtual std::vector<std::shared_ptr<Change>> List() const = 0;
    
    // Add change将提供的变更追加到变更列表中
    virtual Error Add(const std::shared_ptr<Change>& change) = 0;
    
    // Clear清空当前变更列表
    // archive可以作为目录路径提供，以在该位置保存changelist的副本
    virtual Error Clear(const std::string& archive) = 0;
    
    // Remove删除与给定索引对应的变更
    virtual Error Remove(const std::vector<int>& idxs) = 0;
    
    // Close同步任何待写入到底层存储的内容并关闭文件/连接
    virtual Error Close() = 0;
    
    // NewIterator返回一个迭代器，用于遍历当前存储的变更列表
    virtual std::unique_ptr<ChangeIterator> NewIterator() = 0;
    
    // Location返回changelist存储的位置
    virtual std::string Location() const = 0;
};

// TUFChange - Change接口的具体实现
class TUFChange : public Change {
private:
    std::string action_;
    std::string scope_;
    std::string type_;
    std::string path_;
    std::vector<uint8_t> content_;

public:
    TUFChange(const std::string& action, const std::string& scope, 
              const std::string& type, const std::string& path, 
              const std::vector<uint8_t>& content)
        : action_(action), scope_(scope), type_(type), path_(path), content_(content) {}
    
    std::string Action() const override { return action_; }
    std::string Scope() const override { return scope_; }
    std::string Type() const override { return type_; }
    std::string Path() const override { return path_; }
    const std::vector<uint8_t>& Content() const override { return content_; }
    std::vector<uint8_t>  Serialize() const override;
};

// TUFRootData - 用于root角色变更的数据结构
struct TUFRootData {
    RoleName RoleName;
    std::vector<std::shared_ptr<crypto::PublicKey>> Keys;
    std::vector<uint8_t> Serialize() const;
};

// FileChangelist - 基于文件系统的Changelist实现
class FileChangelist : public Changelist {
private:
    std::string dir_;

public:
    explicit FileChangelist(const std::string& dir);
    
    std::vector<std::shared_ptr<Change>> List() const override;
    Error Add(const std::shared_ptr<Change>& change) override;
    Error Clear(const std::string& archive) override;
    Error Remove(const std::vector<int>& idxs) override;
    Error Close() override;
    std::unique_ptr<ChangeIterator> NewIterator() override;
    std::string Location() const override { return dir_; }
};


} // namespace changelist
} // namespace notary
