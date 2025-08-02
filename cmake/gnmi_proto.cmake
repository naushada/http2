# gNMI Proto CMake Module
# This file provides protobuf compilation targets for gNMI proto files

# Set up protobuf import directories for gNMI
set(GNMI_PROTO_DIR 
	"${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto/gnmi"
	"${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto/gnmi_ext"
	"${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto/target"
	"${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto/collector"
)
set(GNMI_IMPORT_DIRS 
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi"
)

    
# Generate C++ files
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${GNMI_PROTO_DIR}
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
    IMPORT_DIRS ${GNMI_IMPORT_DIRS}
)
    
# Create a library target for this proto
add_library(gnmi_proto STATIC ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(gnmi_proto ${PROTOBUF_LIBRARIES})
target_include_directories(gnmi_proto PUBLIC 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROTOBUF_INCLUDE_DIRS}
)
    
# Set variables for use in main CMakeLists.txt
set(GNMI_PROTO_INCLUDE_DIRS 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROTOBUF_INCLUDE_DIRS}
)

set(GNMI_PROTO_LIBRARIES 
    gnmi_proto
    ${PROTOBUF_LIBRARIES}
)

# Print status
message(STATUS "gNMI proto files configured")
message(STATUS "  Proto directory: ${GNMI_PROTO_DIR}")
message(STATUS "  Import directories: ${GNMI_IMPORT_DIRS}") 
