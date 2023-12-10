#pragma once

#include <list>
#include <shared_mutex>
#include <string>

#include "datasource.hpp"
#include "memhelper.hpp"

#include "yara.h"

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

    void Scan(DataSource& ds, std::list<std::string>& detections);
    void SetRules(const std::list<std::string>& rules);

    YaraScanner() :
        mCompiledRules(nullptr, yr_rules_destroy), mScanner(nullptr, yr_scanner_destroy)
    {}

protected:

    std::unique_ptr<YR_SCANNER, void(*)(YR_SCANNER* scanner)> mScanner;

    std::unique_ptr<YR_RULES, int(*)(YR_RULES* scanner)> mCompiledRules;
    std::shared_mutex mRulesLock;
};

void ScanUsingYara(YaraScanner& scanner, HANDLE hProcess, const MemoryHelperBase::MemInfoT64& region, std::list<std::string>& result);
void SetYaraRules(YaraScanner& scanner, const std::list<std::string>& rules);
