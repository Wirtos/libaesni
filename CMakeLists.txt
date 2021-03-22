cmake_minimum_required(VERSION 3.10)
list(APPEND CMAKE_ASM_NASM_SOURCE_FILE_EXTENSIONS s)
project(libaesni LANGUAGES C ASM_NASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (NOT "${CMAKE_ASM_NASM_COMPILER_ID}" MATCHES "YASM")
    message(FATAL_ERROR "-DCMAKE_ASM_NASM_ASM variable must point to a yasm assembler, currently points to: ${CMAKE_ASM_NASM_COMPILER_ID}")
endif ()

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Only 64 bit targets are supported")
endif ()

add_library(${PROJECT_NAME}_asm OBJECT asm/iaesx64.s asm/do_rdtsc.s)
if (UNIX)
    target_compile_options(${PROJECT_NAME}_asm PRIVATE -D__linux__)
endif ()

add_library(${PROJECT_NAME} src/intel_aes.c $<TARGET_OBJECTS:${PROJECT_NAME}_asm>)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        include
        )
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME})


add_executable(test EXCLUDE_FROM_ALL test/test_libaesni.c)
target_link_libraries(test PRIVATE ${PROJECT_NAME})
