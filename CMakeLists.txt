cmake_minimum_required(VERSION 3.6)

project(MemScanner)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(COMMON_SRC source/datasource.cpp
               source/file.cpp
               source/log.cpp
               source/memhelper.cpp
               source/memdatasource.cpp
               source/ntdll64.cpp
               source/pe.cpp
               include/datasource.hpp
               include/file.hpp
               include/log.hpp
               include/memdatasource.hpp
               include/memhelper.hpp
               include/ntdll64.hpp
               include/pe.hpp
               include/system_defs.hpp
               include/scanner.hpp    
)

set(SCANNER_SRC source/main.cpp
                source/scanner.cpp
                ${COMMON_SRC}
)

set(SUSP_THREAD_SRC source/scanner.cpp
                    tests/susp_thread_test.cpp            
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

add_executable(memscan ${SCANNER_SRC})
add_executable(susp_thread_test ${SUSP_THREAD_SRC})
add_executable(datasource_test ${DATASRC_SRC})
add_executable(peimage_test ${PEIMAGE_SRC})
add_executable(pefile_test ${PEFILE_SRC})
add_executable(private_pe_test ${PRIVATE_PE_SRC})
add_executable(sections_artifacts_test ${SECTION_ARTIFACTS_SRC})
add_executable(single_page_test ${SINGLE_PAGE_SRC})

set(NTDLL64LL ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)

set(MEMSCAN_LINKER_FLAGS "/level='highestAvailable' /uiAccess='false'")
set_target_properties(memscan PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")

set_target_properties(susp_thread_test PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
set_target_properties(datasource_test PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
set_target_properties(peimage_test PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
set_target_properties(pefile_test PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
set_target_properties(sections_artifacts_test PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
set_target_properties(single_page_test PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")

if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_link_libraries(susp_thread_test ${NTDLL64LL})
    target_link_libraries(datasource_test ${NTDLL64LL})
    target_link_libraries(memscan ${NTDLL64LL})
    target_link_libraries(peimage_test ${NTDLL64LL})
    target_link_libraries(pefile_test ${NTDLL64LL})
    target_link_libraries(private_pe_test ${NTDLL64LL})
    target_link_libraries(sections_artifacts_test ${NTDLL64LL})
    target_link_libraries(single_page_test ${NTDLL64LL})
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
