# Protobuf Setup for gNMI Integration

This document explains how to resolve the protobuf import error: `Import "github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto" was not found or had errors.`

## Problem

The gNMI proto files use GitHub-style import paths like:
```protobuf
import "github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto";
```

When compiling these files, the protobuf compiler needs to know where to find these imports.

## Solution

### 1. Install Protocol Buffers

#### Windows (using Chocolatey):
```powershell
choco install protoc
```

#### Windows (manual installation):
1. Download from: https://github.com/protocolbuffers/protobuf/releases
2. Extract to a directory (e.g., `C:\protobuf`)
3. Add `C:\protobuf\bin` to your PATH environment variable

#### Using vcpkg:
```powershell
vcpkg install protobuf
```

### 2. Configure Import Paths

The project now includes:
- Updated `CMakeLists.txt` with proper protobuf configuration
- `compile_proto.bat` (Windows) and `compile_proto.sh` (Linux/Mac) scripts

### 3. Compile Protobuf Files

#### Using the provided script (Windows):
```powershell
.\compile_proto.bat
```

#### Manual compilation:
```powershell
protoc -I"third_party\gnmi\proto" -I"third_party\gnmi" --cpp_out=. your_file.proto
```

### 4. Example: Compile gNMI Proto Files

```powershell
# Compile gnmi.proto
protoc -I"third_party\gnmi\proto" -I"third_party\gnmi" --cpp_out=. third_party\gnmi\proto\gnmi\gnmi.proto

# Compile gnmi_ext.proto
protoc -I"third_party\gnmi\proto" -I"third_party\gnmi" --cpp_out=. third_party\gnmi\proto\gnmi_ext\gnmi_ext.proto
```

### 5. CMake Integration

The updated `CMakeLists.txt` includes:
- Protobuf package finding
- Proper include directories
- Import path configuration

### 6. Build the Project

```powershell
mkdir build
cd build
cmake ..
cmake --build .
```

## File Structure

```
http2/
├── third_party/
│   └── gnmi/                    # Git submodule
│       └── proto/
│           ├── gnmi/
│           │   └── gnmi.proto   # Main gNMI definitions
│           ├── gnmi_ext/
│           │   └── gnmi_ext.proto  # gNMI extensions
│           └── ...
├── CMakeLists.txt               # Updated with protobuf config
├── compile_proto.bat            # Windows compilation script
├── compile_proto.sh             # Linux/Mac compilation script
└── README_PROTOBUF.md           # This file
```

## Troubleshooting

### Import not found errors:
1. Ensure protobuf compiler is installed and in PATH
2. Verify the import paths are correct
3. Check that the gNMI submodule is properly initialized:
   ```powershell
   git submodule update --init --recursive
   ```

### CMake errors:
1. Install CMake if not already installed
2. Ensure protobuf development libraries are installed
3. On Windows, you may need to set `CMAKE_PREFIX_PATH` to point to protobuf installation

## Next Steps

After setting up protobuf:
1. Compile the gNMI proto files you need
2. Include the generated `.pb.h` files in your C++ code
3. Link against the protobuf libraries in your build system 