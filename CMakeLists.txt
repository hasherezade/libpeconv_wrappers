cmake_minimum_required ( VERSION 2.8 )

# replace "peconv_project" by your own project name:
project ( peconv_project )

# libs
# modules:
set ( M_PARSER "libpeconv/libpeconv" )
set ( M_WRAPPER "pewrappers" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE FILE "PEConvLib library path" )

set (WRAPPERS_DIR "${CMAKE_SOURCE_DIR}/${M_WRAPPER}" CACHE PATH "PEWrappers main path")
add_subdirectory ( ${WRAPPERS_DIR} )
set ( WRAPPERS_LIB $<TARGET_FILE:pewrappers> CACHE FILE "PEWrappers library path" )

# Add sub-directories
#
add_subdirectory ( template )
add_subdirectory ( pewrappers/protect )

