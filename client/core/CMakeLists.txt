cmake_minimum_required(VERSION 3.20)

project(mjolnir_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "Mjolnir C++ core currently targets Windows only.")
endif()

include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(nlohmann_json)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(mjolnir_core
    main.cpp
    config.cpp
)

add_executable(mjolnir_watchdog
    watchdog_main.cpp
)

target_include_directories(mjolnir_core
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(mjolnir_watchdog
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(mjolnir_core
    PRIVATE
        nlohmann_json::nlohmann_json
        wintrust
        crypt32
        dwmapi
        ntdll
        advapi32
        psapi
        bcrypt
)

target_link_libraries(mjolnir_watchdog
    PRIVATE
        ntdll
)

target_compile_definitions(mjolnir_core
    PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
)

target_compile_definitions(mjolnir_watchdog
    PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
)

if(MSVC)
    target_compile_options(mjolnir_core PRIVATE /W4 /permissive- /EHsc)
    target_compile_options(mjolnir_watchdog PRIVATE /W4 /permissive- /EHsc)
else()
    target_compile_options(mjolnir_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(mjolnir_watchdog PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_custom_command(
    TARGET mjolnir_core
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/whitelist.json
        $<TARGET_FILE_DIR:mjolnir_core>/whitelist.json
    COMMAND ${CMAKE_COMMAND} -E make_directory
        $<TARGET_FILE_DIR:mjolnir_core>/log
    COMMAND ${CMAKE_COMMAND} -E make_directory
        $<TARGET_FILE_DIR:mjolnir_core>/baselines
)

