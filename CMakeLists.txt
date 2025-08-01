cmake_minimum_required(VERSION 3.16.3)
project(dm)

#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a -g -Wall -Wextra")

# Find Protobuf
find_package(Protobuf REQUIRED)

# Add subdirectory for gNMI
add_subdirectory(third_party/gnmi)

include_directories(inc)
include_directories(${PROTOBUF_INCLUDE_DIRS})

# Set up protobuf import directories for gNMI
set(PROTOBUF_IMPORT_DIRS 
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi"
)

# Set protobuf import path environment variable
set(ENV{PROTOBUF_IMPORT_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto")

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.cpp")

add_executable(dm ${SOURCES})
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi)
target_link_libraries(dm pthread ssl crypto ${PROTOBUF_LIBRARIES})

add_subdirectory(test)

install(TARGETS dm
	    CONFIGURATIONS Release
        RUNTIME DESTINATION /usr/local/bin
)