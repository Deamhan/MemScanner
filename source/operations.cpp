#include "../include/operations.hpp"

const char* OperationTypeToText(OperationType operation)
{
    switch (operation)
    {
    case OperationType::Alloc:
        return "AllocOperation";
    case OperationType::Protect:
        return "ProtectOperation";
    case OperationType::CreateThread:
        return "CreateThreadOperation";
    case OperationType::Apc:
        return "ApcOperation";
    case OperationType::Write:
        return "WriteOperation";
    default:
        return "UnknownOperation";
    }
}
