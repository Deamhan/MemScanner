cmake_minimum_required(VERSION 3.6)

project(wow64helper)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(SRC source/main.cpp
        source/ntdll64.cpp
        include/ntdll64.h
        include/system_defs.h
)

add_executable(wow64demo ${SRC})

target_link_libraries(wow64demo ${PROJECT_SOURCE_DIR}/lib/ntdll64ll.obj)
