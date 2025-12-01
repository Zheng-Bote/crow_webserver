cmake_minimum_required(VERSION 3.31)
project(CrowQtServer 
    VERSION 0.1.1
    LANGUAGES CXX)

#CXX=clang++ cmake ..
# make -j$(nproc)


# --- Compiler Settings ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra)
endif()

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

# --- Executable ---
add_executable(${PROJECT_NAME} main.cpp)

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
