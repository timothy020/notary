#include "notary/utils/logger.hpp"
#include <ctime>
#include <cstdlib>

namespace notary {
namespace utils {

// 获取当前时间字符串的工具函数实现
std::string GetTimeString() {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
        
    std::tm now_tm;
#ifdef _WIN32
    localtime_s(&now_tm, &now_time_t);
#else
    localtime_r(&now_time_t, &now_tm);
#endif
    
    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    return ss.str();
}

// LogLevel相关函数实现
LogLevel ParseLogLevel(const std::string& level) {
    if (level == "debug" || level == "DEBUG") return LogLevel::Debug;
    if (level == "info" || level == "INFO") return LogLevel::Info;
    if (level == "warn" || level == "WARN" || level == "warning" || level == "WARNING") return LogLevel::Warn;
    if (level == "error" || level == "ERROR") return LogLevel::Error;
    if (level == "fatal" || level == "FATAL") return LogLevel::Fatal;
    if (level == "panic" || level == "PANIC") return LogLevel::Panic;
    
    // 默认为Info级别
    return LogLevel::Info;
}

std::string LogLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
        case LogLevel::Panic: return "PANIC";
        default: return "UNKNOWN";
    }
}

// JSONFormatter实现
std::string JSONFormatter::Format(const LogEntry& entry) {
    using json = nlohmann::json;
    
    json j = {
        {"level", LogLevelToString(entry.level)},
        {"time", entry.time},
        {"msg", entry.message}
    };
    
    // 添加额外字段
    for (const auto& field : entry.fields) {
        j[field.first] = field.second;
    }
    
    return j.dump();
}

// TextFormatter实现
std::string TextFormatter::Format(const LogEntry& entry) {
    std::stringstream ss;
    ss << "[" << entry.time << "] " 
       << "[" << LogLevelToString(entry.level) << "] "
       << entry.message;
    
    // 添加额外字段
    if (!entry.fields.empty()) {
        ss << " {";
        bool first = true;
        for (const auto& field : entry.fields) {
            if (!first) ss << ", ";
            ss << field.first << "=" << field.second;
            first = false;
        }
        ss << "}";
    }
    
    return ss.str();
}

// ConsoleOutput实现
void ConsoleOutput::Write(const std::string& message) {
    std::cout << message << std::endl;
}

// FileOutput实现
FileOutput::FileOutput(const std::string& filename) {
    file_.open(filename, std::ios::app);
    if (!file_.is_open()) {
        std::cerr << "无法打开日志文件: " << filename << std::endl;
    }
}

FileOutput::~FileOutput() {
    if (file_.is_open()) {
        file_.close();
    }
}

void FileOutput::Write(const std::string& message) {
    if (file_.is_open()) {
        file_ << message << std::endl;
        file_.flush();
    }
}

// LogContext实现
void LogContext::WithField(const std::string& key, const std::string& value) {
    fields_[key] = value;
}

LogContext LogContext::With(const std::string& key, const std::string& value) const {
    LogContext newContext = *this;
    newContext.WithField(key, value);
    return newContext;
}

// LogEntryBuilder实现
LogEntryBuilder::LogEntryBuilder(LogLevel level, std::string message)
    : level_(level), message_(std::move(message)) {}

LogEntryBuilder& LogEntryBuilder::WithField(const std::string& key, const std::string& value) {
    fields_[key] = value;
    return *this;
}

LogEntry LogEntryBuilder::Build() const {
    LogEntry entry;
    entry.level = level_;
    entry.message = message_;
    entry.time = GetTimeString();
    entry.fields = fields_;
    return entry;
}

// Logger实现
Logger::Logger() {
    // 默认添加控制台输出
    AddOutput(std::make_unique<ConsoleOutput>());
    // 默认使用JSON格式
    SetFormatter(std::make_unique<JSONFormatter>());
}

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

void Logger::Initialize(const std::string& level, const std::string& format, const std::string& output) {
    // 设置日志级别
    SetLevel(level);
    
    // 设置格式化器
    if (format == "json") {
        SetFormatter(std::make_unique<JSONFormatter>());
    } else {
        SetFormatter(std::make_unique<TextFormatter>());
    }
    
    // 清除现有输出
    outputs_.clear();
    
    // 设置输出
    if (output == "file" && !output.empty()) {
        AddOutput(std::make_unique<FileOutput>("notary-server.log"));
    } else {
        AddOutput(std::make_unique<ConsoleOutput>());
    }
}

void Logger::SetLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

void Logger::SetLevel(const std::string& level) {
    SetLevel(ParseLogLevel(level));
}

LogLevel Logger::GetLevel() const {
    return level_;
}

void Logger::AddOutput(std::unique_ptr<LogOutput> output) {
    std::lock_guard<std::mutex> lock(mutex_);
    outputs_.push_back(std::move(output));
}

void Logger::SetFormatter(std::unique_ptr<LogFormatter> formatter) {
    std::lock_guard<std::mutex> lock(mutex_);
    formatter_ = std::move(formatter);
}

void Logger::Log(const LogEntry& entry) {
    if (!ShouldLog(entry.level)) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    if (formatter_) {
        std::string formatted = formatter_->Format(entry);
        for (auto& output : outputs_) {
            output->Write(formatted);
        }
    }
    
    // 如果是Panic级别，直接终止程序
    if (entry.level == LogLevel::Panic) {
        std::exit(1);
    }
}

void Logger::Log(LogLevel level, const std::string& message, const LogContext& ctx) {
    if (!ShouldLog(level)) return;
    
    LogEntry entry;
    entry.level = level;
    entry.message = message;
    entry.time = GetTimeString();
    
    // 合并上下文字段
    entry.fields = ctx.Fields();
    for (const auto& field : context_.Fields()) {
        // 只在不存在时添加全局上下文字段
        if (entry.fields.find(field.first) == entry.fields.end()) {
            entry.fields[field.first] = field.second;
        }
    }
    
    Log(entry);
}

void Logger::Debug(const std::string& message, const LogContext& ctx) {
    Log(LogLevel::Debug, message, ctx);
}

void Logger::Info(const std::string& message, const LogContext& ctx) {
    Log(LogLevel::Info, message, ctx);
}

void Logger::Warn(const std::string& message, const LogContext& ctx) {
    Log(LogLevel::Warn, message, ctx);
}

void Logger::Error(const std::string& message, const LogContext& ctx) {
    Log(LogLevel::Error, message, ctx);
}

void Logger::Fatal(const std::string& message, const LogContext& ctx) {
    Log(LogLevel::Fatal, message, ctx);
}

void Logger::Panic(const std::string& message, const LogContext& ctx) {
    Log(LogLevel::Panic, message, ctx);
}

bool Logger::AdjustLogLevel(bool increment) {
    std::lock_guard<std::mutex> lock(mutex_);
    int currentLevel = static_cast<int>(level_);
    
    if (increment) {
        if (currentLevel >= static_cast<int>(LogLevel::Debug)) {
            return false; // 已经是最高级别
        }
        currentLevel++;
    } else {
        if (currentLevel <= static_cast<int>(LogLevel::Panic)) {
            return false; // 已经是最低级别
        }
        currentLevel--;
    }
    
    level_ = static_cast<LogLevel>(currentLevel);
    return true;
}

Logger& Logger::WithContext(const LogContext& ctx) {
    // 修改自身而不是创建新实例
    for (const auto& field : ctx.Fields()) {
        context_.WithField(field.first, field.second);
    }
    return *this;
}

Logger& Logger::WithField(const std::string& key, const std::string& value) {
    // 修改自身而不是创建新实例
    context_.WithField(key, value);
    return *this;
}

bool Logger::ShouldLog(LogLevel level) const {
    return static_cast<int>(level) <= static_cast<int>(level_);
}

} // namespace utils
} // namespace notary 