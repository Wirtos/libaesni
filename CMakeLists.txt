cmake_minimum_required(VERSION 3.13)
list(APPEND CMAKE_ASM_NASM_SOURCE_FILE_EXTENSIONS S s)
project(libaesni LANGUAGES C ASM_NASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME}_asm OBJECT asm/iaesx64.s asm/do_rdtsc.s)
if (NOT ${CMAKE_C_COMPILER_ID} MATCHES "MSVC")
    target_compile_options(${PROJECT_NAME}_asm PRIVATE -D__linux__)
endif ()

add_library(${PROJECT_NAME} src/intel_aes.c $<TARGET_OBJECTS:${PROJECT_NAME}_asm>)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        )
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME})


add_executable(test EXCLUDE_FROM_ALL test/test_libaesni.c)
target_link_libraries(test PRIVATE ${PROJECT_NAME})
