cmake_minimum_required(VERSION 3.21)

project(cmaper VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CMAPER_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(CMAPER_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(CMAPER_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

find_package(LibXml2 REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

set(CMAPER_SOURCE_LIST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/sources.list")
if(NOT EXISTS "${CMAPER_SOURCE_LIST_FILE}")
    message(FATAL_ERROR "sources.list not found at ${CMAPER_SOURCE_LIST_FILE}")
endif()

file(STRINGS "${CMAPER_SOURCE_LIST_FILE}" CMAPER_SOURCES)
list(FILTER CMAPER_SOURCES EXCLUDE REGEX "^[ \t]*#")
list(FILTER CMAPER_SOURCES EXCLUDE REGEX "^[ \t]*$")

add_executable(cmaper ${CMAPER_SOURCES})

target_include_directories(cmaper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBXML2_INCLUDE_DIRS}
)

target_link_libraries(cmaper PRIVATE
    LibXml2::LibXml2
    SQLite::SQLite3
    Threads::Threads
)

if(MSVC)
    target_compile_options(cmaper PRIVATE /W4)
    if(CMAPER_WARNINGS_AS_ERRORS)
        target_compile_options(cmaper PRIVATE /WX)
    endif()
else()
    target_compile_options(cmaper PRIVATE -Wall -Wextra -Wpedantic)
    if(CMAPER_WARNINGS_AS_ERRORS)
        target_compile_options(cmaper PRIVATE -Werror)
    endif()
    if(CMAPER_ENABLE_ASAN)
        target_compile_options(cmaper PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(cmaper PRIVATE -fsanitize=address)
    endif()
    if(CMAPER_ENABLE_UBSAN)
        target_compile_options(cmaper PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(cmaper PRIVATE -fsanitize=undefined)
    endif()
endif()

install(TARGETS cmaper RUNTIME DESTINATION bin)
