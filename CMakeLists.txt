cmake_minimum_required(VERSION 3.24)
project(CppShieldyExampleWinApi)

set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_FLAGS "-fno-ident -s -O3 -fno-ident -fdata-sections -ffunction-sections -fvisibility=hidden -fvisibility-inlines-hidden -Wl,--gc-sections -Wl,--strip-all")
set(CMAKE_CXX_FLAGS "-g -D_DEBUG")
#set(CMAKE_CXX_FLAGS "-fsanitize=address")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--output-def,CppShieldyExampleWinApi.def")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xlinker -Map=CppShieldyExampleWinApi.map")

add_executable(CppShieldyExampleWinApi main_test.cpp
        shieldy_api.cpp
        shieldy_api.h
        libraries/ecdh.c
        libraries/ChaCha20-Poly1305.cpp
        libraries/sha256.cpp
        libraries/sha256.h)
target_link_libraries(CppShieldyExampleWinApi -lCrypt32 -lbcrypt)
target_link_libraries(CppShieldyExampleWinApi -static)
