cmake_minimum_required(VERSION 3.23...3.30)

# cmake -S ../src -B . -DCMAKE_BUILD_TYPE=Debug
# make -j$(nproc)


project(CrowQtServer 
    VERSION 0.4.0
    DESCRIPTION "Crow Webserver with Qt6 for photo uploads"
    HOMEPAGE_URL "https://github.com/Zheng-Bote/crow_webserver"
    LANGUAGES CXX)


# --- Compiler Settings ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(EXECUTABLE_NAME "${PROJECT_NAME}")
set(PROG_LONGNAME "write Binary formats")
set(PROG_CREATED "2025")
set(PROG_AUTHOR "ZHENG Bote")
set(PROG_ORGANIZATION_NAME "ZHENG Robert")
set(PROG_ORGANIZATION_DOMAIN "net.hase-zheng")
find_package(QT NAMES Qt6 REQUIRED COMPONENTS Core)
set(CMAKE_QTV "${QT_VERSION_MAJOR}.${QT_VERSION_MINOR}.${QT_VERSION_PATCH}")

#if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
#    set(CMAKE_CXX_COMPILER /usr/bin/clang++)
#    add_compile_options(-Wall -Wextra)
#    message(STATUS "Using Clang ${CMAKE_CXX_COMPILER}")
#endif()

add_subdirectory(configure)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
message(STATUS "Using Clang")   
    add_compile_options(-Wall -Wextra)
endif()
message(STATUS "Using Compiler: ${CMAKE_CXX_COMPILER}")

# --- Dependencies via FetchContent ---
include(FetchContent)

# ---------------------------------------------------------
# 1. ASIO (Wichtig: VOR Crow laden!)
# Crow benötigt Asio (Standalone). Wir laden es hier manuell,
# damit wir nicht auf System-Pakete (libasio-dev) angewiesen sind.
# ---------------------------------------------------------
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-30-2  # Aktuelle stabile Version
)
FetchContent_MakeAvailable(asio)

# FIX FÜR CROW:
# Crow nutzt ein eigenes "Findasio.cmake", das nach ASIO_INCLUDE_DIR sucht.
# Wir setzen diese Variable manuell auf den Pfad, den FetchContent gerade geladen hat.
set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)

# ---------------------------------------------------------
# 2. Crow
# ---------------------------------------------------------
FetchContent_Declare(
    crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(crow)

# ---------------------------------------------------------
# 3. JWT-CPP
# ---------------------------------------------------------
FetchContent_Declare(
    jwt-cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG        v0.7.0
)
FetchContent_MakeAvailable(jwt-cpp)

# ---------------------------------------------------------
# 4. LibBcrypt
# ---------------------------------------------------------
FetchContent_Declare(
    libbcrypt
    GIT_REPOSITORY https://github.com/trusch/libbcrypt.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(libbcrypt)

# --- System Dependencies ---
find_package(OpenSSL REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core Sql)

add_compile_definitions(QT_NO_KEYWORDS)
# --- Executable ---
add_executable(${PROJECT_NAME} main.cpp
    includes/rz_dbmanager.hpp
    includes/rz_dbmanager.cpp
    includes/rz_middleware.hpp
    includes/rz_helpers.hpp
)

# WICHTIG: Asio Include Directories auch zum eigenen Target hinzufügen,
# da Crow Header diese inkludieren.
target_include_directories(${PROJECT_NAME} PRIVATE ${ASIO_INCLUDE_DIR} ${libbcrypt_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Crow::Crow
    jwt-cpp::jwt-cpp
    bcrypt
    Qt6::Core
    Qt6::Sql
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Linux Deploy Helper
set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# the end
message(
  "Build with CMake version: ${CMAKE_VERSION} and ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} c++${CMAKE_CXX_STANDARD} QT ${CMAKE_QTV}"
)
include(ProcessorCount)
ProcessorCount(N)
message("number of processors: " ${N})
message("cmake --build . --parallel ${N}")

