@echo off
REM Script to compile protobuf files with correct import paths for gNMI

REM Set the base directory
set BASE_DIR=%~dp0

REM Set protobuf import paths
set IMPORT_PATHS=-I"%BASE_DIR%third_party\gnmi\proto" -I"%BASE_DIR%third_party\gnmi"

echo Compiling protobuf files with import paths:
echo %IMPORT_PATHS%

REM Example: Compile a proto file
REM protoc %IMPORT_PATHS% --cpp_out=. your_file.proto

REM For specific gNMI files, you can use:
REM protoc %IMPORT_PATHS% --cpp_out=. third_party\gnmi\proto\gnmi\gnmi.proto
REM protoc %IMPORT_PATHS% --cpp_out=. third_party\gnmi\proto\gnmi_ext\gnmi_ext.proto

echo Usage: protoc %IMPORT_PATHS% --cpp_out=. ^<your_proto_file^> 