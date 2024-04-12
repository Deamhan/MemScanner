rule GenericShellcode32 {
  strings:
    $SelfPos = { e8 ?? 00 00 00 }
    $FsReadPeb = { 64 8b ?? 30}
    $FsReadTeb = { 64 8b ?? 18}
    $ReadLdr = { 8b ?? 0c }
    $ModuleLoadOrderList = { 8b ?? 0c }
    $ModuleMemOrderList = { 8b ?? 14 }
    $ModuleInitOrderList = { 8b ?? 1c }
  condition:
    (OperationRangeEnd - OperationRangeStart <= 4096) and ((MemoryAttributes & XFlag) != 0) and $SelfPos and ($FsReadTeb or $FsReadPeb) and $ReadLdr and ($ModuleLoadOrderList or $ModuleMemOrderList or $ModuleInitOrderList)
 }
 