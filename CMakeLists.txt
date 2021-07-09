cmake_minimum_required(VERSION 3.6)

project(wow64helper)

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

add_executable(memscan ${SCANNER_SRC})
add_executable(test1 ${TEST1_SRC})

target_link_libraries(memscan ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)
set(MEMSCAN_LINKER_FLAGS "/level='highestAvailable' /uiAccess='false'")
set_target_properties(memscan PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")

target_link_libraries(test1 ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)
set_target_properties(test1 PROPERTIES LINK_FLAGS "${MEMSCAN_LINKER_FLAGS}")

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT memscan)

enable_testing()
add_test(NAME self_detection COMMAND test1)
