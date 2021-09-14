cmake_minimum_required(VERSION 3.18)

project(dkvs VERSION 0)
include(cmake/StandardProjectSettings.cmake)

add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_20)

add_library(project_warnings INTERFACE)
include(cmake/CompilerWarnings.cmake)
set_project_warnings(project_warnings)
include(cmake/Sanitizers.cmake)
enable_sanitizers(project_options)
include(cmake/StaticAnalyzers.cmake)

set(CORE src/dkvs.cpp)

add_library(dkvscore ${CORE})
target_compile_definitions(dkvscore PUBLIC DOCTEST_CONFIG_DISABLE)
target_include_directories(dkvscore PUBLIC src)
target_link_libraries(dkvscore PRIVATE project_options project_warnings)

add_executable(dkvs src/dkvs-main.cpp)
target_compile_definitions(dkvs PUBLIC DOCTEST_CONFIG_DISABLE)
target_link_libraries(dkvs PRIVATE project_options project_warnings dkvscore uring)
target_include_directories(dkvs PUBLIC src)

add_executable(utest src/dkvs-test.cpp src/test-main.cpp ${CORE})
target_include_directories(utest PUBLIC src)
target_link_libraries(utest PRIVATE project_options project_warnings)

add_executable(ring src/iouring_example2.cpp)
target_link_libraries(ring PRIVATE project_options uring)

add_executable(iouring_example src/iouring_example.cpp)
target_link_libraries(iouring_example PRIVATE project_options uring)
