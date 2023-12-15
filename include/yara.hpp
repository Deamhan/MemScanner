#pragma once

#include <list>
#include <shared_mutex>
#include <string>
#include <utility>

#include "datasource.hpp"
#include "memhelper.hpp"

#include "yara.h"

class YaraScanner
{
public:
    // can be shared between scanners
    class YaraRules
    {
    public:
        YaraRules(const std::list<std::string>& rules);
        YaraRules(const wchar_t* directory);

        void SetRules(const std::list<std::string>& rules);
        void SetRules(const wchar_t* directory);

        using AutoUnlock = std::unique_ptr<std::shared_mutex, void(*)(std::shared_mutex*)>;
        using LockedRules = std::pair<YR_RULES*, AutoUnlock>;
        LockedRules LockCompiledRules();

    private:
        std::unique_ptr<YR_RULES, int(*)(YR_RULES*)> mCompiledRules;
        std::shared_mutex mLock;

        void SetIntVariable(YR_COMPILER* compiler, const char* name, int value);
        void SetStringVariable(YR_COMPILER* compiler, const char* name, const char* value);
    };

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

    void SetIntVariable(const char* name, int value);
    void SetStringVariable(const char* name, const char* value);
    void Scan(DataSource& ds, std::list<std::string>& detections);

    YaraScanner(std::shared_ptr<YaraRules> rules);

protected:
    std::unique_ptr<YR_SCANNER, void(*)(YR_SCANNER* scanner)> mScanner;
    std::shared_ptr<YaraRules> mRules;
    std::unique_ptr<YaraRules::LockedRules> mLockedRules;
};

void ScanUsingYara(YaraScanner& scanner, HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result);
std::unique_ptr<YaraScanner> BuildYaraScanner(const std::list<std::string>& rules);
std::unique_ptr<YaraScanner> BuildYaraScanner(const wchar_t* rootDir);
