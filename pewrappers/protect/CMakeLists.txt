cmake_minimum_required (VERSION 2.8)

project ( protect )

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	aes_crypt.cpp
	rtlcompress.cpp
	main.cpp
)

set (hdrs
	aes_crypt.h
	rtlcompress.h
	protect.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

