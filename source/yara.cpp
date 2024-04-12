#include "stdafx.h"

#include "../include/yara.hpp"

#include <algorithm>
#include <shared_mutex>

#include "../include/file.hpp"
#include "../include/log.hpp"
#include "../include/memdatasource.hpp"

#include "yara.h"

static const uint8_t* FetchDataFunc(YR_MEMORY_BLOCK* self) noexcept
{
    return (const uint8_t*)self->context;
}

struct IteratorContext
{
    DataSource& Ds;  
    YR_MEMORY_BLOCK Result;
    uint64_t FileSize;

    static thread_local std::vector<uint8_t> Buffer;

    IteratorContext(DataSource& ds) : Ds(ds), FileSize(ds.GetSize())
    {
        Result.fetch_data = FetchDataFunc;
    }
};

thread_local std::vector<uint8_t> IteratorContext::Buffer(1024 * 1024);

static YR_MEMORY_BLOCK* DataIteratorFunc(YR_MEMORY_BLOCK_ITERATOR* self) noexcept
{
    try
    {
        auto context = (IteratorContext*)self->context;
        auto& ds = context->Ds;
        auto& buffer = context->Buffer;
        auto& result = context->Result;
        auto fileSize = context->FileSize;

        result.base = ds.GetOffset();
        result.size = (size_t)std::min<uint64_t>(buffer.size(), fileSize - result.base);

        if (result.size == 0)
            return nullptr;

        result.context = buffer.data();

        ds.Read(result.context, result.size);

        return &result;
    }
    catch (...)
    {
        return nullptr;
    }
}

static uint64_t GetSizeFunc(YR_MEMORY_BLOCK_ITERATOR* self) noexcept
{
    auto context = (IteratorContext*)self->context;
    return context->FileSize;
}

static int YaraCallback(
    YR_SCAN_CONTEXT* /*context*/,
    int message,
    void* message_data,
    void* user_data)
{
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;

    auto rule = (YR_RULE*)message_data;
    auto name = rule->identifier;

    auto& detections = *(std::set<std::string>*)user_data;
    detections.emplace(name);

    return CALLBACK_CONTINUE;
}

static void CompilerCallback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* /*user_data*/)
{
    const wchar_t* msg_type = L"error";
    LoggerBase::Level level = LoggerBase::Error;
    if (error_level == YARA_ERROR_LEVEL_WARNING)
    {
        msg_type = L"warning";
        level = LoggerBase::Info;
    }

    if (rule != nullptr)
    {
        GetDefaultLogger()->Log(level,
            L"%s: rule \"%S\" in %S(%d): %S" LOG_ENDLINE_STR,
            msg_type,
            rule->identifier,
            file_name == nullptr ? "unknown" : file_name,
            line_number,
            message);
    }
    else
    {
        GetDefaultLogger()->Log(level,
            L"%S(%d): %s: %S" LOG_ENDLINE_STR,
            file_name == nullptr ? "unknown" : file_name,
            line_number,
            msg_type,
            message);
    }
}

void YaraScanner::SetIntVariable(const char* name, int value)
{
    auto result = yr_scanner_define_integer_variable(mScanner.get(), name, value);
    if (ERROR_SUCCESS != result)
        throw YaraScannerException{ result, "unable to create external variable (int, scanner)" };
}

void YaraScanner::SetStringVariable(const char* name, const char* value)
{
    auto result = yr_scanner_define_string_variable(mScanner.get(), name, value);
    if (ERROR_SUCCESS != result)
        throw YaraScannerException{ result, "unable to create external variable (string, scanner)" };
}

void YaraScanner::Scan(DataSource& ds, std::set<std::string>& detections)
{
    if (!mScanner)
        throw YaraScannerException{ 0, "scanner is empty" };

    yr_scanner_set_callback(mScanner.get(), YaraCallback, &detections);

    detections.clear();

    ds.Seek(0);
    IteratorContext iteratorContext(ds);

    YR_MEMORY_BLOCK_ITERATOR iterator;
    iterator.context = &iteratorContext;
    iterator.file_size = GetSizeFunc;
    iterator.first = DataIteratorFunc;
    iterator.next = DataIteratorFunc;
    iterator.last_error = ERROR_SUCCESS;

    auto res = yr_scanner_scan_mem_blocks(mScanner.get(), &iterator);
    if (res != ERROR_SUCCESS)
        throw YaraScannerException{ res, "unable to scan memory" };
}

void YaraScanner::ScanProcess(uint32_t pid, std::set<std::string>& detections)
{
    if (!mScanner)
        throw YaraScannerException{ 0, "scanner is empty" };

    yr_scanner_set_callback(mScanner.get(), YaraCallback, &detections);

    detections.clear();
    auto res = yr_scanner_scan_proc(mScanner.get(), pid);
    if (res != ERROR_SUCCESS)
        throw YaraScannerException{ res, "unable to scan memory" };
}

void YaraScanner::YaraRules::SetIntVariable(YR_COMPILER* compiler, const char* name, int value)
{
    auto result = yr_compiler_define_integer_variable(compiler, name, value);
    if (ERROR_SUCCESS != result)
        throw YaraScannerException{ result, "unable to create external variable (int, rule)" };
}

void YaraScanner::YaraRules::SetStringVariable(YR_COMPILER* compiler, const char* name, const char* value)
{
    auto result = yr_compiler_define_string_variable(compiler, name, value);
    if (ERROR_SUCCESS != result)
        throw YaraScannerException{ result, "unable to create external variable (string, rule)" };
}

void YaraScanner::YaraRules::SetRules(const std::list<std::string>& rules)  
{
    YR_COMPILER* compiler = nullptr;
    auto res = yr_compiler_create(&compiler);
    if (res != ERROR_SUCCESS)
        throw YaraScannerException{ res, "unable to create compiler" };

    std::unique_ptr<YR_COMPILER, void(*)(YR_COMPILER* scanner)> compilerGuard(compiler,
        yr_compiler_destroy);
    yr_compiler_set_callback(compiler, CompilerCallback, nullptr);

    SetIntVariable(compiler, "XFlag", MemoryHelperBase::XFlag);
    SetIntVariable(compiler, "RFlag", MemoryHelperBase::RFlag);
    SetIntVariable(compiler, "WFlag", MemoryHelperBase::WFlag);

    SetIntVariable(compiler, "ImageType", (int)SystemDefinitions::MemType::Image);
    SetIntVariable(compiler, "MappedType", (int)SystemDefinitions::MemType::Mapped);
    SetIntVariable(compiler, "PrivateType", (int)SystemDefinitions::MemType::Private);

    for (int i = 0; i < (int)OperationType::Max; ++i)
        SetIntVariable(compiler, OperationTypeToText((OperationType)i), i);

    SetIntVariable(compiler, "MemoryAttributes", 0);
    SetIntVariable(compiler, "MemoryType", 0);
    SetIntVariable(compiler, "OperationType", (int)OperationType::Unknown);
    SetIntVariable(compiler, "ExternalOperation", 0);
    SetIntVariable(compiler, "AlignedAllocation", 0);
    SetIntVariable(compiler, "OperationRangeStart", 0);
    SetIntVariable(compiler, "OperationRangeEnd", 0);


    for (const auto& rule : rules)
    {
        res = yr_compiler_add_string(compiler, rule.c_str(), nullptr);
        if (res != ERROR_SUCCESS)
            throw YaraScannerException{ res, std::string("unable to add rule ").append(rule).c_str() };
    }

    YR_RULES* compiledRules = nullptr;
    res = yr_compiler_get_rules(compiler, &compiledRules);
    if (res != ERROR_SUCCESS)
        throw YaraScannerException{ res, "unable to compile rules" };

    mCompiledRules.reset(compiledRules);
}

void YaraScanner::YaraRules::SetRules(const wchar_t* directory)
{
    std::wstring root(directory);
    if (root.empty())
        throw YaraScannerException{ 0, "directory is empty" };

    if (*root.rbegin() != L'\\')
        root += L'/';

    std::wstring pattern(root);
    pattern += L"*.yara";

    WIN32_FIND_DATAW data;
    auto searchHandle = FindFirstFileW(pattern.c_str(), &data);

    if (searchHandle == INVALID_HANDLE_VALUE)
        throw YaraScannerException{ (int)GetLastError(), "unable to enumerate rules directory" };

    std::unique_ptr<HANDLE, void(*)(HANDLE*)> searchGuard(&searchHandle, MemoryHelperBase::CloseSearchHandleByPtr);
    std::list<std::string> rules;

    do
    {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            continue;

        File file((root + data.cFileName).c_str(), File::OpenForRead, 0);
        std::string text(data.nFileSizeLow, '\0');
        auto read = file.Read(&text[0], text.size());
        text.resize(read);

        // remove UTF8 BOM if present
        if (text.size() > 3 && text.compare(0, 3, "\xEF\xBB\xBF") == 0)
            text.erase(0, 3);

        rules.push_back(std::move(text));

    } while (FindNextFileW(searchHandle, &data) != FALSE);

    SetRules(rules);
}

YaraScanner::YaraRules::YaraRules(const std::list<std::string>& rules)
    : mCompiledRules(nullptr, yr_rules_destroy)
{
    SetRules(rules);
}

YaraScanner::YaraRules::YaraRules(const wchar_t* directory)
    : mCompiledRules(nullptr, yr_rules_destroy)
{
    SetRules(directory);
}

YaraScanner::YaraScanner(std::shared_ptr<YaraRules> rules) :
    mScanner(nullptr, yr_scanner_destroy), mRules(std::move(rules))
{
    if (!mRules)
        throw YaraScannerException(0, "rules cannot be empty");

    YR_SCANNER* scanner = nullptr;
    auto error = yr_scanner_create(mRules->GetCompiledRules(), &scanner);
    if (error != ERROR_SUCCESS)
        throw YaraScannerException(error, "unable to create a scanner");

    mScanner.reset(scanner);
    yr_scanner_set_flags(scanner, SCAN_FLAGS_REPORT_RULES_MATCHING | SCAN_FLAGS_PROCESS_MEMORY);

    const int TimeoutInSeconds = 1;
    yr_scanner_set_timeout(scanner, TimeoutInSeconds);
}

class YaraInitializer
{
public:
    YaraInitializer()
    {
        yr_initialize();
    }

    ~YaraInitializer()
    {
        yr_finalize();
    }
} yaraSharedInit;

std::unique_ptr<YaraScanner> BuildYaraScanner(const std::list<std::string>& rules)
{
    try
    {
        return std::make_unique<YaraScanner>(std::make_shared<YaraScanner::YaraRules>(rules));
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\t\tYARA exception: %S (%d)" LOG_ENDLINE_STR, e.what(), e.GetErrorCode());
    }

    return nullptr;
}

std::unique_ptr<YaraScanner> BuildYaraScanner(const wchar_t* rootDir)
{
    try
    {
        return std::make_unique<YaraScanner>(std::make_shared<YaraScanner::YaraRules>(rootDir));
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\t\tYARA exception: %S (%d)" LOG_ENDLINE_STR, e.what(), e.GetErrorCode());
    }
    catch (const DataSourceException& e)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\t\tYARA exception (data access): %d" LOG_ENDLINE_STR, e.GetErrorCode());
    }

    return nullptr;
}

void ScanUsingYara(YaraScanner& scanner, HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region,
    std::set<std::string>& result, uint64_t& startAddress, uint64_t& size, OperationType operation,
    bool externalOperation, bool isAlignedAllocation)
{
    result.clear();

    try
    {
        if (startAddress == 0)
            startAddress = region.BaseAddress;

        if (size == 0)
            size = (region.BaseAddress + region.RegionSize) - startAddress;

        ReadOnlyMemoryDataSource dsForYara(hProcess, region.BaseAddress, region.RegionSize, 0);

        auto startRangeRva = startAddress - region.BaseAddress;
        scanner.SetIntVariable("OperationRangeStart", (int)startRangeRva);
        scanner.SetIntVariable("OperationRangeEnd", (int)(startRangeRva + size));

        scanner.SetIntVariable("MemoryAttributes", MemoryHelperBase::protToFlags(region.Protect));
        scanner.SetIntVariable("MemoryType", (int)region.Type);

        scanner.SetIntVariable("OperationType", (int)operation);
        if (externalOperation)
            scanner.SetIntVariable("ExternalOperation", 1);
        if (isAlignedAllocation)
            scanner.SetIntVariable("AlignedAllocation", 1);

        scanner.Scan(dsForYara, result);
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\t\tYARA exception: %S (%d)" LOG_ENDLINE_STR, e.what(), e.GetErrorCode());
    }
}

void ScanProcessUsingYara(YaraScanner& scanner, uint32_t pid, std::set<std::string>& result)
{
    result.clear();

    try
    {
        scanner.ScanProcess(pid, result);
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(LoggerBase::Error, L"\t\tYARA exception: %S (%d)" LOG_ENDLINE_STR, e.what(), e.GetErrorCode());
    }
}
