cmake_minimum_required(VERSION 3.18)
project(dkvs VERSION 0)

find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS src/dkvs.proto)

include(cmake/StandardProjectSettings.cmake)
add_library(project_options INTERFACE)
target_compile_features(project_options INTERFACE cxx_std_20)
add_library(project_warnings INTERFACE)
include(cmake/CompilerWarnings.cmake)
set_project_warnings(project_warnings)
include(cmake/Sanitizers.cmake)
enable_sanitizers(project_options)
include(cmake/StaticAnalyzers.cmake)

set(CORE src/command.cpp src/dkvs.cpp src/fdcloser.cpp
         src/kv.cpp src/pb.cpp src/iouring.cpp)

add_library(pb ${PROTO_SRCS})
target_include_directories(pb PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pb PRIVATE project_options)

add_library(dkvscore ${CORE})
target_compile_definitions(dkvscore PUBLIC DOCTEST_CONFIG_DISABLE)
target_include_directories(dkvscore PUBLIC ${CMAKE_CURRENT_BINARY_DIR} src)
target_link_libraries(dkvscore PRIVATE project_options project_warnings)

add_executable(dkvs src/dkvs-main.cpp)
target_compile_definitions(dkvs PUBLIC DOCTEST_CONFIG_DISABLE)
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    target_link_libraries(dkvs PRIVATE project_options project_warnings
        dkvscore pb ${Protobuf_LITE_LIBRARY} uring)
else()
    target_link_libraries(dkvs PRIVATE project_options project_warnings dkvscore pb)
endif()
target_include_directories(dkvs PUBLIC src)

add_executable(utest src/dkvs-test.cpp src/test-main.cpp ${CORE})
target_include_directories(utest PUBLIC ${CMAKE_CURRENT_BINARY_DIR} src)
target_link_libraries(utest PRIVATE project_options project_warnings
    pb ${Protobuf_LITE_LIBRARY} uring)
