cmake_minimum_required(VERSION 3.24)
project(CppShieldyExampleWinApi)

set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_FLAGS "-fno-ident -s -O3 -fno-ident -fdata-sections -ffunction-sections -fvisibility=hidden -fvisibility-inlines-hidden -Wl,--gc-sections -Wl,--strip-all")
set(CMAKE_CXX_FLAGS "-g -D_DEBUG")
#set(CMAKE_CXX_FLAGS "-fsanitize=address")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--output-def,CppShieldyExampleWinApi.def")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xlinker -Map=CppShieldyExampleWinApi.map")

set(SECP256K1_DISABLE_SHARED ON)
set(SECP256K1_BUILD_BENCHMARK OFF)
set(SECP256K1_BUILD_TESTS OFF)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF)

add_subdirectory(libraries/secp256k1)

add_executable(CppShieldyExampleWinApi main.cpp
        game/board.cpp
        game/board.h
        shieldy_api.cpp
        shieldy_api.h
        libraries/ecdh.c
        libraries/ChaCha20-Poly1305.cpp
        libraries/sha256.cpp
        libraries/sha256.h
        libraries/ecdh_utils.h)

target_include_directories(CppShieldyExampleWinApi PUBLIC libraries/secp256k1/include)

target_link_libraries(CppShieldyExampleWinApi -lCrypt32 -lbcrypt)
target_link_libraries(CppShieldyExampleWinApi -static)
target_link_libraries(CppShieldyExampleWinApi secp256k1)