#pragma once

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <mutex>
#include <map>
#include <vector>
#include <chrono>
#include <iomanip>
#include <nlohmann/json.hpp>

namespace notary {
namespace utils {

// 日志级别枚举
enum class LogLevel : int {
    Panic = 0,    // 最严重的错误，导致应用程序终止
    Fatal = 1,    // 严重错误，但可能不会终止程序
    Error = 2,    // 错误但可恢复
    Warn  = 3,    // 警告
    Info  = 4,    // 信息性消息
    Debug = 5     // 调试信息
};

// 获取当前时间字符串的工具函数
std::string GetTimeString();

// 日志条目结构
struct LogEntry {
    LogLevel level;
    std::string message;
    std::string time;
    std::map<std::string, std::string> fields;
};

// 日志格式化器接口
class LogFormatter {
public:
    virtual ~LogFormatter() = default;
    virtual std::string Format(const LogEntry& entry) = 0;
};

// JSON格式化器
class JSONFormatter : public LogFormatter {
public:
    std::string Format(const LogEntry& entry) override;
};

// 文本格式化器
class TextFormatter : public LogFormatter {
public:
    std::string Format(const LogEntry& entry) override;
};

// 日志输出接口
class LogOutput {
public:
    virtual ~LogOutput() = default;
    virtual void Write(const std::string& message) = 0;
};

// 控制台输出
class ConsoleOutput : public LogOutput {
public:
    void Write(const std::string& message) override;
};

// 文件输出
class FileOutput : public LogOutput {
public:
    explicit FileOutput(const std::string& filename);
    ~FileOutput();
    void Write(const std::string& message) override;

private:
    std::ofstream file_;
};

// 日志上下文
class LogContext {
public:
    LogContext() = default;
    LogContext(std::map<std::string, std::string> fields) : fields_(std::move(fields)) {}
    
    // 获取字段
    const std::map<std::string, std::string>& Fields() const { return fields_; }
    
    // 添加字段
    void WithField(const std::string& key, const std::string& value);
    
    // 创建带有新字段的上下文
    LogContext With(const std::string& key, const std::string& value) const;

private:
    std::map<std::string, std::string> fields_;
};

// 日志条目构建器
class LogEntryBuilder {
public:
    LogEntryBuilder(LogLevel level, std::string message);
    
    // 添加字段
    LogEntryBuilder& WithField(const std::string& key, const std::string& value);
    
    // 构建日志条目
    LogEntry Build() const;
    
private:
    LogLevel level_;
    std::string message_;
    std::map<std::string, std::string> fields_;
};

// 主日志类
class Logger {
public:
    // 获取单例实例
    static Logger& GetInstance();
    
    // 初始化日志系统
    void Initialize(const std::string& level, const std::string& format, const std::string& output);
    
    // 设置日志级别
    void SetLevel(LogLevel level);
    void SetLevel(const std::string& level);
    
    // 获取当前日志级别
    LogLevel GetLevel() const;
    
    // 添加日志输出
    void AddOutput(std::unique_ptr<LogOutput> output);
    
    // 设置格式化器
    void SetFormatter(std::unique_ptr<LogFormatter> formatter);
    
    // 日志方法
    void Log(const LogEntry& entry);
    void Log(LogLevel level, const std::string& message, const LogContext& ctx = LogContext());
    
    // 各级别日志方法
    void Debug(const std::string& message, const LogContext& ctx = LogContext());
    void Info(const std::string& message, const LogContext& ctx = LogContext());
    void Warn(const std::string& message, const LogContext& ctx = LogContext());
    void Error(const std::string& message, const LogContext& ctx = LogContext());
    void Fatal(const std::string& message, const LogContext& ctx = LogContext());
    void Panic(const std::string& message, const LogContext& ctx = LogContext());
    
    // 调整日志级别
    bool AdjustLogLevel(bool increment);
    
    // 创建带上下文的日志器 - 返回引用而非拷贝
    Logger& WithContext(const LogContext& ctx);
    Logger& WithField(const std::string& key, const std::string& value);

private:
    Logger();
    ~Logger() = default;
    
    // 禁止拷贝和移动
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;
    
    LogLevel level_ = LogLevel::Info;
    std::vector<std::unique_ptr<LogOutput>> outputs_;
    std::unique_ptr<LogFormatter> formatter_;
    LogContext context_;
    std::mutex mutex_;
    
    // 检查是否应该记录该级别的日志
    bool ShouldLog(LogLevel level) const;
};

// 便捷获取日志实例的辅助函数
inline Logger& GetLogger() {
    return Logger::GetInstance();
}

// 从字符串解析日志级别
LogLevel ParseLogLevel(const std::string& level);

// 获取日志级别名称
std::string LogLevelToString(LogLevel level);

} // namespace utils
} // namespace notary 