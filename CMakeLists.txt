cmake_minimum_required(VERSION 3.21)

project(cmaper VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CMAPER_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

find_package(LibXml2 REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

set(CMAPER_SOURCES
    src/main.c
    src/app/app.c
    src/cli/config.c
    src/cli/diagnostic.c
    src/cli/help.c
    src/cli/parser.c
    src/cli/raw.c
    src/cli/validate.c
    src/core/error.c
    src/core/log.c
    src/output/sink.c
    src/platform/clipboard.c
    src/platform/fs.c
    src/platform/terminal.c
    src/preflight/check.c
    src/runtime/context.c
    src/runtime/paths.c
    src/security/extract.c
    src/security/nmap_extract.c
    src/scan/artifact.c
    src/scan/command.c
    src/scan/detail.c
    src/scan/detail_targets.c
    src/scan/heartbeat.c
    src/scan/nmap_xml_model.c
    src/scan/nmap_xml_parse.c
    src/scan/nmap_xml_utils.c
    src/scan/options.c
    src/scan/plan.c
    src/scan/process.c
    src/scan/runner.c
    src/scan/source_identity.c
    src/snapshot/schema.c
    src/snapshot/security.c
    src/snapshot/store.c
    src/snapshot/write.c
    src/history/alerts.c
    src/history/delete.c
    src/history/diff.c
    src/history/domain.c
    src/history/fuzzy.c
    src/history/query.c
    src/history/render.c
    src/history/service.c
)

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
endif()

install(TARGETS cmaper RUNTIME DESTINATION bin)
