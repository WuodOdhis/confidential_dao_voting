cmake_minimum_required(VERSION 3.16)
project(tee-app)
set(CMAKE_CXX_STANDARD 17)
add_executable(tee-app src/main.cpp)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
target_include_directories(tee-app PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(tee-app ${SODIUM_LIBRARIES})



