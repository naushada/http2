cmake_minimum_required(VERSION 3.16.3)
project(dm)
find_package(Protobuf REQUIRED)
find_package(GTest REQUIRED)

include_directories(../inc)
include_directories(inc)
#include_directories(../third_party/gnmi)

set(PROTO_DIR "../third_party/gnmi/proto")
message(STATUS "Proto PATH: " ${PROTO_DIR})
set(PROTO_FILES 
    "${PROTO_DIR}/gnmi/gnmi.proto"
    "${PROTO_DIR}/gnmi_ext/gnmi_ext.proto"
    "${PROTO_DIR}/collector/collector.proto")

include_directories(${PROTOBUF_INCLUDE_DIRS})
message(STATUS "Include PATH: " ${PROTOBUF_INCLUDE_DIRS})

# Place to look for proto files
set(PROTOBUF_IMPORT_DIRS "${PROTO_DIR}/gnmi_ext" 
                         "${PROTO_DIR}/collector" 
                         "${PROTO_DIR}/gnmi")

set(PROTO_INCLUDE_DIRS "${PROTO_DIR}")
protobuf_generate_cpp(PROTO_SRCS  PROTO_HDRS ${PROTO_FILES})

message(STATUS "HDRS PATH: " ${PROTO_HDRS})
message(STATUS "SRCS PATH: " ${PROTO_SRCS})

#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a -g -Wall -Wextra")
#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.cpp" "../src/services.cpp" 
                              "../src/services_http.cpp"
                              "../src/services_lwm2m.cpp"
                              "../src/command_line_argument.cpp"
                              )

enable_testing()

add_executable(dm_test ${PROTO_SRCS} ${PROTO_HDRS} ${SOURCES} )
target_link_libraries(dm_test gtest_main)
target_link_libraries(dm_test pthread)
target_link_libraries(dm_test ssl crypto)
target_link_libraries(dm_test gtest)
#target_link_libraries(dm_test gnmi)

add_test(dm_gtests dm_test)
gtest_discover_tests(dm_test)