rule GenericShellcode {
  strings:
    $SelfPos = { e8 ?? 00 00 00 }
    $GsRead = { 65 48 8b }
    $ReadLdr = { 48 8b ?? 18 }
    $ModuleLoadOrderList = { 48 8b ?? 10 }
    $ModuleMemOrderList = { 48 8b ?? 20 }
    $ModuleInitOrderList = { 48 8b ?? 30 }
  condition:
    (filesize <= 4096) and ((MemoryAttributes & XFlag) != 0) and (MemoryType == PrivateType) and $SelfPos and $GsRead and $ReadLdr and ($ModuleLoadOrderList or $ModuleMemOrderList or $ModuleInitOrderList)
 }
 