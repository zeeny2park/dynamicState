cmake_minimum_required(VERSION 3.10)
project(dynamicstate-collector C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_definitions(-D_GNU_SOURCE)

include_directories(include)

add_executable(dynamicstate-collector
    src/collector.c
    src/main.c
)

install(TARGETS dynamicstate-collector DESTINATION bin)
