cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -Wall -Wextra")

add_executable(oppg_1 oppg_1.cpp)

add_executable(oppg_2 oppg_2.cpp)
#target_link_libraries(oppg_2 ${OPENSSL_CRYPTO_LIBRARY})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
add_executable(oppg_3 oppg_3.cpp)
target_link_libraries(oppg_3 ${OPENSSL_CRYPTO_LIBRARY})
