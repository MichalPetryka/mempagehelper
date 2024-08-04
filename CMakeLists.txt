cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0092 NEW)
cmake_policy(SET CMP0077 NEW)

project(mempagehelper)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif ()

enable_language(C)

# Warning settings
if (MSVC)
	message("Enabling MSVC warnings")
	add_compile_options(/W4 /WX)
else ()
	message("Enabling non-MSVC warnings")
	add_compile_options(-Wall -Wextra -pedantic -Werror)
endif ()

# MSVC settings
if (MSVC)
	message("Enabling MSVC UTF-8")
	add_compile_options(/utf-8)
endif ()

# Windows settings
if (WIN32)
	message("Enabling Windows configuration")
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
	if (NOT MSVC)
		SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static -static-libgcc")
	endif ()
	add_definitions(-DUNICODE -D_UNICODE)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	add_definitions(-DNTDDI_VERSION=NTDDI_WIN7 -DWINVER=_WIN32_WINNT_WIN7 -D_WIN32_WINNT=_WIN32_WINNT_WIN7)
endif ()

include_directories(include)
file(GLOB_RECURSE SOURCES "src/*.cpp")
add_library(mempagehelper SHARED ${SOURCES})

include(CheckIPOSupported)
check_ipo_supported(RESULT result OUTPUT output)
if(result)
  set_property(TARGET mempagehelper PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(WARNING "IPO is not supported: ${output}")
endif()

if (WIN32)
	set_target_properties(mempagehelper PROPERTIES PREFIX "")
	set_target_properties(mempagehelper PROPERTIES IMPORT_PREFIX "")
else ()
	set_target_properties(mempagehelper PROPERTIES PREFIX "lib")
	set_target_properties(mempagehelper PROPERTIES IMPORT_PREFIX "lib")
endif ()
