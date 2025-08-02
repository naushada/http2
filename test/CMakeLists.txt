cmake_minimum_required(VERSION 3.16.3)
project(dm)
find_package(Protobuf REQUIRED)
find_package(GTest REQUIRED)

include_directories(../inc)
include_directories(inc)
include_directories(${GNMI_PROTO_INCLUDE_DIRS})

message(STATUS "Include PATH: " ${GNMI_PROTO_INCLUDE_DIRS})


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
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi)

add_executable(dm_test ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dm_test gtest_main)
target_link_libraries(dm_test pthread)
target_link_libraries(dm_test ssl crypto)
target_link_libraries(dm_test gtest)
target_link_libraries(dm_test ${GNMI_PROTO_LIBRARIES})


add_test(dm_gtests dm_test)
gtest_discover_tests(dm_test)