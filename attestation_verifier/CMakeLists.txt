cmake_minimum_required(VERSION 3.5)

if(NOT DEFINED ENV{SOURCE_DATE_EPOCH})
  set(ENV{SOURCE_DATE_EPOCH} "1750600413")
endif()

add_compile_definitions(
  __DATE__=\"\"
  __TIME__=\"\"
)

set(_src_root ${CMAKE_SOURCE_DIR})

add_compile_options(
  -Wdate-time -Werror=date-time
  -ffile-prefix-map=${_src_root}=.
  -fdebug-prefix-map=${_src_root}=.
)


include(FetchContent)
project(AttestationClient)
set(CMAKE_PROJECT_TARGET AttestationClient)
add_definitions (-DPLATFORM_UNIX)
add_link_options(-Wl,--build-id=none)

include_directories(
     /usr/include/azguestattestation1
)

fetchcontent_declare(jwt-cpp 
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG 08bcf77a687fb06e34138e9e9fa12a4ecbe12332 # v0.7.0 release
)
set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "disable building examples" FORCE)
fetchcontent_makeavailable(jwt-cpp)

link_directories (
    /usr/lib
    /usr/lib/x86_64-linux-gnu
)

add_executable(${CMAKE_PROJECT_TARGET} main.cpp
					                             Logger.cpp
                                       )

target_link_libraries(${CMAKE_PROJECT_TARGET} azguestattestation -lz)
target_link_libraries(${CMAKE_PROJECT_TARGET} curl)
target_link_libraries(${CMAKE_PROJECT_TARGET} jwt-cpp::jwt-cpp)
target_link_libraries(${CMAKE_PROJECT_TARGET} crypto)
target_link_libraries(${CMAKE_PROJECT_TARGET} ssl )