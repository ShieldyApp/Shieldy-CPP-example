cmake_minimum_required(VERSION 3.24)
project(CppShieldyExampleWinApi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-fno-ident -s -O3 -fno-ident -fdata-sections -ffunction-sections -fvisibility=hidden -fvisibility-inlines-hidden -Wl,--gc-sections -Wl,--strip-all")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--output-def,CppShieldyExampleWinApi.def")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xlinker -Map=CppShieldyExampleWinApi.map")

add_executable(CppShieldyExampleWinApi main.cpp shieldy_cpp_api.cpp shieldy_cpp_api.h board.cpp)
target_link_libraries(CppShieldyExampleWinApi -lCrypt32 -lbcrypt)
target_link_libraries(CppShieldyExampleWinApi -static)
