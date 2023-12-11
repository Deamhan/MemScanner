#include "yara.hpp"

#include <shared_mutex>

#include "file.hpp"
#include "log.hpp"
#include "memdatasource.hpp"

#include "yara.h"

static const uint8_t* FetchDataFunc(YR_MEMORY_BLOCK* self) noexcept
{
    return (const uint8_t*)self->context;
}

struct IteratorContext
{
    DataSource& Ds;
    std::vector<uint8_t> Buffer;
    YR_MEMORY_BLOCK Result;
    uint64_t FileSize;

    IteratorContext(DataSource& ds, size_t bufferSize) : Ds(ds), Buffer(bufferSize), FileSize(ds.GetSize())
    {
        Result.fetch_data = FetchDataFunc;
    }
};

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

    auto& detections = *(std::list<std::string>*)user_data;
    detections.emplace_back(name);

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
    ILogger::Level level = ILogger::Error;
    if (error_level == YARA_ERROR_LEVEL_WARNING)
    {
        msg_type = L"warning";
        level = ILogger::Info;
    }

    if (rule != nullptr)
    {
        GetDefaultLogger()->Log(level,
            L"%s: rule \"%S\" in %S(%d): %S\n",
            msg_type,
            rule->identifier,
            file_name == nullptr ? "unknown" : file_name,
            line_number,
            message);
    }
    else
    {
        GetDefaultLogger()->Log(level,
            L"%S(%d): %s: %S\n",
            file_name == nullptr ? "unknown" : file_name,
            line_number,
            msg_type,
            message);
    }
}

void YaraScanner::Scan(DataSource& ds, std::list<std::string>& detections)
{
    std::shared_lock<std::shared_mutex> lg(mRulesLock);

    if (!mScanner)
        throw YaraScannerException{ 0, "scanner is empty" };

    yr_scanner_set_callback(mScanner.get(), YaraCallback, &detections);

    detections.clear();

    ds.Seek(0);
    IteratorContext iteratorContext(ds, 1024 * 1024);

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

void YaraScanner::SetRules(const std::list<std::string>& rules)
{
    std::unique_lock<std::shared_mutex> lg(mRulesLock);

    YR_COMPILER* compiler = nullptr;
    auto res = yr_compiler_create(&compiler);
    if (res != ERROR_SUCCESS)
        throw YaraScannerException{ res, "unable to create compiler" };

    std::unique_ptr<YR_COMPILER, void(*)(YR_COMPILER* scanner)> compilerGuard(compiler,
        yr_compiler_destroy);
    yr_compiler_set_callback(compiler, CompilerCallback, nullptr);

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

    YR_SCANNER* scanner = nullptr;
    res = yr_scanner_create(mCompiledRules.get(), &scanner);
    if (res != ERROR_SUCCESS)
        throw YaraScannerException{ res, "unable to create scanner" };

    mScanner.reset(scanner);
    yr_scanner_set_flags(mScanner.get(), SCAN_FLAGS_REPORT_RULES_MATCHING);

    const int TimeoutInSeconds = 1;
    yr_scanner_set_timeout(mScanner.get(), TimeoutInSeconds);
}

void YaraScanner::LoadRules(const wchar_t* directory)
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
        throw YaraScannerException{ (int)GetLastError(), "unable to enumerate rules directory"};
    
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

void SetYaraRules(YaraScanner& scanner, const std::list<std::string>& rules)
{
    try
    {
        scanner.SetRules(rules);
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"\t\tYARA exception: %S (%d)\n", e.what(), e.GetErrorCode());
    }
}

void LoadYaraRules(YaraScanner& scanner, const wchar_t* rootDir)
{
    try
    {
        scanner.LoadRules(rootDir);
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"\t\tYARA exception: %S (%d)\n", e.what(), e.GetErrorCode());
    }
    catch (const DataSourceException& e)
    {
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"\t\tYARA exception (data access): %d\n", e.GetErrorCode());
    }
}

void ScanUsingYara(YaraScanner& scanner, HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result)
{
    result.clear();

    try
    {
        ReadOnlyMemoryDataSource dsForYara(hProcess, region.BaseAddress, region.RegionSize, 0);
        scanner.Scan(dsForYara, result);
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"\t\tYARA exception: %S (%d)\n", e.what(), e.GetErrorCode());
    }
}
