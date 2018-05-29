cmake_minimum_required (VERSION 2.8)
project (template)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

message (STATUS "wrappers_dir='${WRAPPERS_DIR}'")
message (STATUS "wrappers_lib='${WRAPPERS_LIB}'")

include_directories ( ${PECONV_DIR}/include )
include_directories ( ${WRAPPERS_DIR}/include )

set (srcs
	main.cpp
)

set (hdrs
)

set (rsrc
#    resource.rc
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} )
target_link_libraries ( ${PROJECT_NAME} ${WRAPPERS_LIB} )
add_dependencies( ${PROJECT_NAME} libpeconv pewrappers)

