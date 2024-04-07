#pragma once

enum class OperationType
{
	Unknown,
	Alloc,
	Protect,
	CreateThread,
	Apc,
	Write,
	Max // must be the last
};

const char* OperationTypeToText(OperationType operation);
