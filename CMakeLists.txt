cmake_minimum_required(VERSION 3.16)
project(nirantara C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Compiler flags ────────────────────────────────────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wstrict-prototypes -Wmissing-prototypes
    -fstack-protector-strong
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# ── Dependencies ──────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
pkg_check_modules(SQLITE3   REQUIRED sqlite3)
pkg_check_modules(LIBPQ     REQUIRED libpq)

# ── Subprojects ───────────────────────────────────────────────────────────────
add_subdirectory(lib/nirantara-net)
add_subdirectory(edge)
