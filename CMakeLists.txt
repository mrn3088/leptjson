cmake_minimum_required(VERSION 3.10)

# Set the project name
project(leptjson)

# Set the C standard
set(CMAKE_C_STANDARD 99)

# Add source files
set(SOURCE_FILES leptjson.c)

# Add header files
set(HEADER_FILES leptjson.h)

# Create the main executable
add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})

# Add test files
set(TEST_SOURCE_FILES test.c)

# Create the test executable
add_executable(test ${TEST_SOURCE_FILES} ${SOURCE_FILES} ${HEADER_FILES})

# (Optional) If you want to link any libraries, you can add them here
# target_link_libraries(${PROJECT_NAME} PRIVATE library_name)
# target_link_libraries(leptjson_test PRIVATE library_name)
