cmake_minimum_required(VERSION 3.16.3)
project(dm)

#Adding Complier flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a -g -Wall -Wextra")

add_subdirectory(third_party/gnmi)
include_directories(inc)
include_directories(${PROTOBUF_INCLUDE_DIRS})
# Place to look for proto files
set(PROTOBUF_IMPORT_DIRS "third_party/gnmi/proto/gnmi_ext" 
                         "third_party/gnmi/proto/collector" 
                         "third_party/gnmi/proto/target")

#However, the file(GLOB...) allows for wildcard additions:
file(GLOB SOURCES "src/*.cpp")

add_executable(dm ${SOURCES})
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi)
target_link_libraries(dm pthread ssl crypto gnmi)

add_subdirectory(test)

install(TARGETS dm
	    CONFIGURATIONS Release
        RUNTIME DESTINATION /usr/local/bin
)