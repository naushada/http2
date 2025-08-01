# gNMI Proto CMake Module
# This file provides protobuf compilation targets for gNMI proto files

# Set up protobuf import directories for gNMI
set(GNMI_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi/proto")
set(GNMI_IMPORT_DIRS 
    "${GNMI_PROTO_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gnmi"
)

# Function to compile gNMI proto files
function(compile_gnmi_proto PROTO_FILE)
    get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
    get_filename_component(PROTO_DIR ${PROTO_FILE} DIRECTORY)
    
    # Generate C++ files
    protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE}
        PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
        IMPORT_DIRS ${GNMI_IMPORT_DIRS}
    )
    
    # Create a library target for this proto
    add_library(${PROTO_NAME}_proto STATIC ${PROTO_SRCS} ${PROTO_HDRS})
    target_link_libraries(${PROTO_NAME}_proto ${PROTOBUF_LIBRARIES})
    target_include_directories(${PROTO_NAME}_proto PUBLIC 
        ${CMAKE_CURRENT_BINARY_DIR}
        ${PROTOBUF_INCLUDE_DIRS}
    )
    
    # Add to the main gnmi_protos target
    add_dependencies(gnmi_protos ${PROTO_NAME}_proto)
endfunction()

# Create a custom target for gNMI proto files
add_custom_target(gnmi_protos)

# Compile main gNMI proto files
if(EXISTS "${GNMI_PROTO_DIR}/gnmi/gnmi.proto")
    compile_gnmi_proto("${GNMI_PROTO_DIR}/gnmi/gnmi.proto")
endif()

if(EXISTS "${GNMI_PROTO_DIR}/gnmi_ext/gnmi_ext.proto")
    compile_gnmi_proto("${GNMI_PROTO_DIR}/gnmi_ext/gnmi_ext.proto")
endif()

if(EXISTS "${GNMI_PROTO_DIR}/target/target.proto")
    compile_gnmi_proto("${GNMI_PROTO_DIR}/target/target.proto")
endif()

if(EXISTS "${GNMI_PROTO_DIR}/collector/collector.proto")
    compile_gnmi_proto("${GNMI_PROTO_DIR}/collector/collector.proto")
endif()

# Create a convenience target that includes all gNMI proto libraries
add_library(gnmi_all_protos INTERFACE)
target_link_libraries(gnmi_all_protos INTERFACE 
    gnmi_proto 
    gnmi_ext_proto 
    target_proto 
    collector_proto
)

# Export variables for parent CMakeLists.txt
set(GNMI_PROTO_INCLUDE_DIRS 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROTOBUF_INCLUDE_DIRS}
    PARENT_SCOPE
)

set(GNMI_PROTO_LIBRARIES 
    gnmi_all_protos
    ${PROTOBUF_LIBRARIES}
    PARENT_SCOPE
)

# Print status
message(STATUS "gNMI proto files configured")
message(STATUS "  Proto directory: ${GNMI_PROTO_DIR}")
message(STATUS "  Import directories: ${GNMI_IMPORT_DIRS}") 