#include "yara.hpp"

#include "log.hpp"
#include "memdatasource.hpp"

#ifdef USE_YARA
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

    auto& detections = *(std::vector<std::string>*)user_data;
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
            file_name,
            line_number,
            msg_type,
            message);
    }
}

class YaraScanner
{
public:
    class YaraScannerException : public std::exception
    {
    public:
        YaraScannerException(int code, const char* message = "") :
            std::exception(message), mErrorCode(code)
        {}

        int GetErrorCode() const noexcept { return mErrorCode; }

    protected:
        int mErrorCode;
    };

    static YaraScanner& GetInstance()
    {
        static YaraScanner scanner;
        return scanner;
    }

    void Scan(DataSource& ds, std::list<std::string>& detections)
    {
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

protected:
    YaraScanner() :
        mCompiledRules(nullptr, yr_rules_destroy), mScanner(nullptr, yr_scanner_destroy)
    {
        yr_initialize();
        YR_COMPILER* compiler = nullptr;
        auto res = yr_compiler_create(&compiler);
        if (res != ERROR_SUCCESS)
            throw YaraScannerException{ res, "unable to create compiler" };

        std::unique_ptr<YR_COMPILER, void(*)(YR_COMPILER* scanner)> compilerGuard(compiler,
            yr_compiler_destroy);
        yr_compiler_set_callback(compiler, CompilerCallback, nullptr);

        const char* PeRule = "\
            rule PeSig { \
              strings: \
                $dosText = \"This program cannot be run in DOS mode\" \
                $PeMagic = { 45 50 00 00 } \
                $TextSec = \".text\" \
                $CodeSec = \".code\" \
              condition: \
                ($dosText and ($TextSec or $CodeSec)) or ($PeMagic and ($TextSec or $CodeSec))\
             }";

        res = yr_compiler_add_string(compiler, PeRule, nullptr);
        if (res != ERROR_SUCCESS)
            throw YaraScannerException{ res, "unable to add rule" };

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
    }

    std::unique_ptr<YR_RULES, int(*)(YR_RULES* scanner)> mCompiledRules;
    std::unique_ptr<YR_SCANNER, void(*)(YR_SCANNER* scanner)> mScanner;
};

void ScanUsingYara(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result)
{
    result.clear();

    try
    {
        auto& yaraScanner = YaraScanner::GetInstance();
        ReadOnlyMemoryDataSource dsForYara(hProcess, region.BaseAddress, region.RegionSize, 0);
        yaraScanner.Scan(dsForYara, result);
    }
    catch (const YaraScanner::YaraScannerException& e)
    {
        GetDefaultLoggerForThread()->Log(ILogger::Error, L"\t\tYARA exception: %S (%d)\n", e.what(), e.GetErrorCode());
    }
}

#else

const std::list<std::string>& ScanUsingYara(HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result)
{
    result.clear();
}

#endif // USE_YARA