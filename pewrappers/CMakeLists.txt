cmake_minimum_required (VERSION 2.8)

project ( pewrappers )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

#include own headers
include_directories (
  include
)

set (srcs_protect
	protect/aes_crypt.cpp
	protect/rtlcompress.cpp
)

set (hdrs_protect
	protect/aes_crypt.h
	protect/rtlcompress.h
	protect/protect.h
)

set (srcs
	${srcs_protect}
	pe_wrapper.cpp
	protected_wrapper.cpp
#put your sources here
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	${hdrs_protect}
	include/pe_wrapper.h
	include/protected_wrapper.h
#put your headers here
)

# Choose to build the DLL or EXE

add_library ( ${PROJECT_NAME} STATIC ${hdrs} ${srcs} )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )
