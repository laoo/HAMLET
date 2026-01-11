cmake_minimum_required (VERSION 3.8)

project ("HAMLET")

include_directories( libextern/multiprecision/include )
set(CMAKE_CXX_STANDARD 20)

add_executable (HAMLET "HAMLET.cpp" )

