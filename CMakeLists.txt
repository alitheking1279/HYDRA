cmake_minimum_required(VERSION 3.20)
project(HydraSec)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -------------------
# OpenSSL Setup
# -------------------
set(OPENSSL_ROOT_DIR "E:/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MDd/libssl.lib")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MDd/libcrypto.lib")
else()
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libssl.lib")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.lib")
endif()

# -------------------
# zlib raw source
# -------------------
file(GLOB ZLIB_SRC "zlib/*.c")

# -------------------
# Find OpenCV
# -------------------
set(OpenCV_DIR "E:/opencv/build")   # Path to OpenCVConfig.cmake
find_package(OpenCV REQUIRED)

# -------------------
# PDCurses Setup
# -------------------
set(PDCURSES_ROOT "E:/PDCursesMod-master")        # Root folder contains curses.h
set(PDCURSES_WINCON "E:/PDCursesMod-master/wincon")  # Folder where library was built
set(PDCURSES_INCLUDE_DIR "${PDCURSES_ROOT}")
set(PDCURSES_LIB "${PDCURSES_WINCON}/pdcurses.lib")  # built library

# -------------------
# Add executable
# -------------------
add_executable(hydra
    main.cpp
    ${ZLIB_SRC}
    SQLite/sqlite3.c
)


# -------------------
# Include directories
# -------------------
target_include_directories(hydra PRIVATE 
    ${OPENSSL_INCLUDE_DIR}
    "zlib"
    "SQLite" 
    ${PDCURSES_INCLUDE_DIR}   # points to root for curses.h
    ${OpenCV_INCLUDE_DIRS}
)

# -------------------
# Link libraries
# -------------------
target_link_libraries(hydra PRIVATE
    "${OPENSSL_SSL_LIBRARY}"
    "${OPENSSL_CRYPTO_LIBRARY}"
    ws2_32
    crypt32
    advapi32
    ${OpenCV_LIBS}    
    ${PDCURSES_LIB}
)
