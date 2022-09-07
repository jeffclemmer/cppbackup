cmake_minimum_required (VERSION 2.8.11)

project(cppbackup)

add_subdirectory(cryptopp/)

include_directories(BEFORE tclap-1.2.1/include)

add_executable(cppbackup main.cpp)

link_directories(/usr/local/lib)
target_link_libraries(cppbackup leveldb cryptopp bz2 s3)

install(TARGETS cppbackup RUNTIME DESTINATION bin)