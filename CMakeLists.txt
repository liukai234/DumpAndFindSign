cmake_minimum_required(VERSION 3.21)
project(Dumper)

add_library(dumper SHARED)

target_compile_features(dumper PRIVATE cxx_std_17)
target_compile_options(dumper PRIVATE /utf-8)

target_sources(dumper
	PRIVATE 
		${CMAKE_CURRENT_SOURCE_DIR}/src/dllmain.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/src/mem.cpp
)

target_include_directories(dumper
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include
)

