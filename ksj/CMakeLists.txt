cmake_minimum_required(VERSION 2.6)
project(vm)

set(OUT vm)

set(LINKTYPE STATIC)

add_library ( ${OUT} ${LINKTYPE}
    src/vm.cpp )

set_target_properties(${OUT} PROPERTIES LINKER_LANGUAGE CXX)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -DNDEBUG -Wno-format-truncation -O3 -s")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wno-format-truncation")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()