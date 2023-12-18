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

        YR_RULES* GetCompiledRules() const noexcept { return mCompiledRules.get(); }

    private:
        std::unique_ptr<YR_RULES, int(*)(YR_RULES*)> mCompiledRules;

        void SetIntVariable(YR_COMPILER* compiler, const char* name, int value);
        void SetStringVariable(YR_COMPILER* compiler, const char* name, const char* value);

        void SetRules(const std::list<std::string>& rules);
        void SetRules(const wchar_t* directory);
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
    void ScanProcess(uint32_t pid, std::list<std::string>& detections);

    YaraScanner(std::shared_ptr<YaraRules> rules);

protected:
    std::unique_ptr<YR_SCANNER, void(*)(YR_SCANNER* scanner)> mScanner;
    std::shared_ptr<YaraRules> mRules;
};

void ScanUsingYara(YaraScanner& scanner, HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result);
void ScanProcessUsingYara(YaraScanner& scanner, uint32_t pid, std::list<std::string>& result);

std::unique_ptr<YaraScanner> BuildYaraScanner(const std::list<std::string>& rules);
std::unique_ptr<YaraScanner> BuildYaraScanner(const wchar_t* rootDir);
