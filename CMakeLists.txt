cmake_minimum_required(VERSION 3.6)

project(MemScanner)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(COMMON_SRC source/ntdll64.cpp
               source/scanner.cpp
               include/ntdll64.h
               include/system_defs.h
               include/scanner.h
)

set(SCANNER_SRC source/main.cpp
                ${COMMON_SRC}
)

set(TEST1_SRC source/test1.cpp
              ${COMMON_SRC}
)

set(VIEWER_SRC source/viewer.cpp
               include/system_defs.h
)

if (MSVC)  
    add_compile_options(/Zi   # pdb
                        /W4   # warning level 4
                        /EHsc  # exceptions: sync
                        /J    # use unsigned char
                        /Gd   # use cdecl
                        /we4715 # not all control paths return a value
                        /we4828 # disallow invalid characters
                        /we4473 # <function> : not enough arguments passed for format string 
                        /we4474 # <function> : too many arguments passed for format string 
                        /we4475 # <function> : length modifier <length> cannot be used with type field character <conversion-specifier> in format specifier 
                        /we4476 # <function> : unknown type field character <conversion-specifier> in format specifier 
                        /we4477 # <function> : format string <format-string> requires an argument of type <type>, but variadic argument <position> has type <type>
                        /we4478 # <function> : positional and non-positional placeholders cannot be mixed in the same format string 
                        /we4551 # function call missing argument list
                        /we4775 # nonstandard extension used in format string <format-string> of function <function> 
                        /we4776 # %<conversion-specifier> is not allowed in the format string of function <function>
                        /we4777 # <function> : format string <format-string> requires an argument of type <type>, but variadic argument <position> has type <type> 
                        /we4778 # <function> : unterminated format string <format-string>
                        /we4002 # too many actual parameters for macro 'identifier'
                        /we4003 # not enough actual parameters for macro 'identifier'
                        /we4840 # prinf-like function arg type mismatch
                        /we4309 # truncation of constant value
                        /we4113 # function pointers type mismatch
                        /we4804 # unsafe use of type 'bool' in operation
                        /utf-8  # utf-8 source
                        /wd4201 # disable 'nonstandard extension used: nameless struct/union'
                        /wd4200 # disable 'nonstandard extension used: zero-sized array in struct/union'
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
add_executable(test1 ${TEST1_SRC})
add_executable(viewer ${VIEWER_SRC})

set(NTDLL64LL ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)

set(MEMSCAN_LINKER_FLAGS "/level='highestAvailable' /uiAccess='false'")
set_target_properties(memscan PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")
set_target_properties(test1 PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-D_X64_=1)
else()
    target_link_libraries(test1 ${NTDLL64LL})
    target_link_libraries(memscan ${NTDLL64LL})
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT memscan)

enable_testing()
add_test(NAME self_detection COMMAND test1)
