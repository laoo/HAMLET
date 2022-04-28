cmake_minimum_required (VERSION 3.8)

project ("HAMLET")

find_package( Boost )
include_directories(${Boost_INCLUDE_DIRS})
set(CMAKE_CXX_STANDARD 20)

add_executable (HAMLET "HAMLET.cpp" )

