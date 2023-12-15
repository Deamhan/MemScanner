cmake_minimum_required(VERSION 3.6)

project(MemScanner)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/yara-4.3.2)

set(COMMON_SRC source/callbacks.cpp
               source/datasource.cpp
               source/file.cpp
               source/log.cpp
               source/memhelper.cpp
               source/memdatasource.cpp
               source/ntdll64.cpp
               source/pe.cpp
               source/scanner.cpp
               source/yara.cpp
               include/callbacks.hpp
               include/datasource.hpp
               include/file.hpp
               include/log.hpp
               include/memdatasource.hpp
               include/memhelper.hpp
               include/ntdll64.hpp
               include/pe.hpp
               include/system_defs.hpp
               include/scanner.hpp   
               include/yara.hpp               
)

set(SCANNER_SRC source/main.cpp
                ${COMMON_SRC}
)

set(SUSP_THREAD_SRC tests/susp_thread_test.cpp            
                    ${COMMON_SRC}
)

set(PEFILE_SRC tests/pefile_test.cpp            
               ${COMMON_SRC}
)

set(DATASRC_SRC tests/datasource_test.cpp
                ${COMMON_SRC}
)

set(PEIMAGE_SRC tests/peimage_test.cpp
                ${COMMON_SRC}
)

set(PRIVATE_PE_SRC tests/private_pe.cpp
                   ${COMMON_SRC}
)

set(SECTION_ARTIFACTS_SRC tests/exec_region_artifacts.cpp
                          ${COMMON_SRC}
)

set(SINGLE_PAGE_SRC tests/single_page_test.cpp
                    ${COMMON_SRC}
)

set(SCANNER_ADDR_SRC tests/scanner_addr_test.cpp
                     ${COMMON_SRC}
)

set(YARA_PE_SRC tests/yara_pe_test.cpp
                ${COMMON_SRC}
)

set(YARA_LOADRULES_SRC tests/yara_loadrules_test.cpp
                       ${COMMON_SRC}
)

set(SIMPLE_MT_SRC tests/simple_mt_test.cpp
                  ${COMMON_SRC}
)

set(EXTERNAL_VARS_SRC tests/external_vars_test.cpp
                      ${COMMON_SRC}
)

if (MSVC)  
    add_compile_options(/Zi   # pdb
                        /W4   # warning level 4
                        /EHsc  # exceptions: sync
                        /J    # use unsigned char
                        /Gd   # use cdecl
                        /we4002 # too many actual parameters for macro 'identifier'
                        /we4003 # not enough actual parameters for macro 'identifier'
                        /we4103 # alignment changed after including header, may be due to missing #pragma pack(pop)
                        /we4113 # function pointers type mismatch
                        /we4309 # truncation of constant value
                        /wd4324 # disable 'structure was padded due to __declspec(align())n'
                        /we4473 # <function> : not enough arguments passed for format string 
                        /we4474 # <function> : too many arguments passed for format string 
                        /we4475 # <function> : length modifier <length> cannot be used with type field character <conversion-specifier> in format specifier 
                        /we4476 # <function> : unknown type field character <conversion-specifier> in format specifier 
                        /we4477 # <function> : format string <format-string> requires an argument of type <type>, but variadic argument <position> has type <type>
                        /we4478 # <function> : positional and non-positional placeholders cannot be mixed in the same format string 
                        /we4551 # function call missing argument list
                        /we4715 # not all control paths return a value
                        /we4775 # nonstandard extension used in format string <format-string> of function <function> 
                        /we4776 # %<conversion-specifier> is not allowed in the format string of function <function>
                        /we4777 # <function> : format string <format-string> requires an argument of type <type>, but variadic argument <position> has type <type> 
                        /we4778 # <function> : unterminated format string <format-string>
                        /we4804 # unsafe use of type 'bool' in operation
                        /we4828 # disallow invalid characters
                        /we4840 # prinf-like function arg type mismatch
                        /wd4200 # disable 'nonstandard extension used: zero-sized array in struct/union'
                        /wd4201 # disable 'nonstandard extension used: nameless struct/union'
                        /utf-8  # utf-8 source
                        /MP     # multiprocessor compilation
                        /GF     # enable string pooling
                        /Zc:__cplusplus # https://devblogs.microsoft.com/cppblog/msvc-now-correctly-reports-__cplusplus/
    )
    
    set(RELEASE_LINKER_FLAGS "/LTCG /OPT:REF,ICF /DEBUG")
    set(RELEASE_COMPILER_FLAGS "-DNDEBUG /Ox /Ob2 /Oi /Ot /Oy /GS- /Gy /GL /Gw /MT")
    set(DEBUG_COMPILER_FLAGS "/GS /MTd -D_DEBUG")
    
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_COMPILER_FLAGS}")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_COMPILER_FLAGS}")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_COMPILER_FLAGS}")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${RELEASE_COMPILER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} ${RELEASE_LINKER_FLAGS}")
endif()

add_compile_definitions(YARA_RULES_DIR=L"${PROJECT_SOURCE_DIR}/rules")

add_executable(memscan ${SCANNER_SRC})
add_executable(susp_thread_test ${SUSP_THREAD_SRC})
add_executable(datasource_test ${DATASRC_SRC})
add_executable(peimage_test ${PEIMAGE_SRC})
add_executable(pefile_test ${PEFILE_SRC})
add_executable(private_pe_test ${PRIVATE_PE_SRC})
add_executable(sections_artifacts_test ${SECTION_ARTIFACTS_SRC})
add_executable(single_page_test ${SINGLE_PAGE_SRC})
add_executable(scanner_addr_test ${SCANNER_ADDR_SRC})
add_executable(yara_pe_test ${YARA_PE_SRC})
add_executable(simple_mt_test ${SIMPLE_MT_SRC})
add_executable(yara_loadrules_test ${YARA_LOADRULES_SRC})
add_executable(external_vars_test ${EXTERNAL_VARS_SRC})

set(NTDLL64LL ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)

set(MEMSCAN_LINKER_FLAGS "/level='highestAvailable' /uiAccess='false'")

set (EXECUTABLES memscan
                 susp_thread_test
                 datasource_test
                 peimage_test
                 pefile_test
                 sections_artifacts_test
                 single_page_test
                 scanner_addr_test
                 private_pe_test
                 yara_pe_test
                 simple_mt_test
                 yara_loadrules_test
                 external_vars_test
)

foreach (exec ${EXECUTABLES})
    set_target_properties(${exec} PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
endforeach()


if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    foreach (exec ${EXECUTABLES})
        target_link_libraries(${exec}
            debug ${PROJECT_SOURCE_DIR}/lib/yara-4.3.2/libyara32d.lib
            optimized ${PROJECT_SOURCE_DIR}/lib/yara-4.3.2/libyara32.lib
            general ${NTDLL64LL}
        )
    endforeach()
else()
    foreach (exec ${EXECUTABLES})
        target_link_libraries(${exec}
            debug ${PROJECT_SOURCE_DIR}/lib/yara-4.3.2/libyara64d.lib
            optimized ${PROJECT_SOURCE_DIR}/lib/yara-4.3.2/libyara64.lib
        )
    endforeach()
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT memscan)

enable_testing()
add_test(NAME self_detection COMMAND susp_thread_test)
add_test(NAME datasrc_test COMMAND datasource_test)
add_test(NAME peimagemem_test COMMAND peimage_test)
add_test(NAME pediskfile_test COMMAND pefile_test)
add_test(NAME private_inmem_pe_test COMMAND private_pe_test)
add_test(NAME section_border_artifacts_test COMMAND sections_artifacts_test)
add_test(NAME single_page_mem_test COMMAND single_page_test)
add_test(NAME scanner_address_test COMMAND scanner_addr_test)
add_test(NAME yara_basic_test COMMAND yara_pe_test)
add_test(NAME simple_multithreaded_test COMMAND simple_mt_test)
add_test(NAME yara_load_rules_test COMMAND yara_loadrules_test)
add_test(NAME external_variables_test COMMAND external_vars_test)
