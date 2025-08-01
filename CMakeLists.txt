##
# SPDX-License-Identifier: BSD-3-Clause
#
# https://opensource.org/license/bsd-3-clause
#
# Copyright (C) 2021 Kang Lin <kl222@126.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
##

cmake_minimum_required(VERSION 3.16)

project(coturn)

option (USE_FSTACK "Enable F-Stack support" ON)

if(USE_FSTACK)
    add_definitions(-DUSE_FSTACK)
    MESSAGE(STATUS "F-stack support enabled")
endif()
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)
# TODO: Modify this when the version is released
SET(BUILD_VERSION "4.7.0")

# Find Git Version Patch
IF(EXISTS "${CMAKE_SOURCE_DIR}/.git")
    if(NOT GIT)
        SET(GIT $ENV{GIT})
    endif()
    if(NOT GIT)
        FIND_PROGRAM(GIT NAMES git git.exe git.cmd)
    endif()
    IF(GIT)
        EXECUTE_PROCESS(
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMAND ${GIT} describe --tags
            OUTPUT_VARIABLE GIT_VERSION  OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT GIT_VERSION)
            EXECUTE_PROCESS(
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                COMMAND ${GIT} rev-parse --short HEAD
                OUTPUT_VARIABLE GIT_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE
            )
        endif()
        SET(BUILD_VERSION ${GIT_VERSION})
    ENDIF()
ENDIF()
string(FIND ${BUILD_VERSION} / BUILD_VERSION_POS REVERSE)
if(BUILD_VERSION_POS GREATER -1)
    math(EXPR BUILD_VERSION_POS "${BUILD_VERSION_POS} + 1")
    string(SUBSTRING ${BUILD_VERSION} ${BUILD_VERSION_POS} -1 BUILD_VERSION)
endif()
message("BUILD_VERSION:${BUILD_VERSION};${_BUILD_VERSION}")
set(VERSION ${BUILD_VERSION})

if(NOT DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif(NOT DEFINED CMAKE_BUILD_TYPE)
string(TOLOWER "${CMAKE_BUILD_TYPE}" build_type)
if("debug" STREQUAL build_type)
    add_definitions(-D_DEBUG)
endif()
if(DEFINED TURN_SERVER_BUILD_INFO)
    add_definitions(-DTURN_SERVER_BUILD_INFO=${TURN_SERVER_BUILD_INFO})
endif()

IF(MSVC)
    # This option is to enable the /MP switch for Visual Studio 2005 and above compilers
    OPTION(WIN32_USE_MP "Set to ON to build with the /MP option (Visual Studio 2005 and above)." ON)
    MARK_AS_ADVANCED(WIN32_USE_MP)
    IF(WIN32_USE_MP)
        #SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
        add_compile_options(/MP)
    ENDIF(WIN32_USE_MP)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
ENDIF(MSVC)

SET(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libs")
if (BUILD_SHARED_LIBS)
    add_definitions(-DBUILD_SHARED_LIBS)
    if (CMAKE_COMPILER_IS_GNUCXX AND NOT MINGW)
       # Just setting CMAKE_POSITION_INDEPENDENT_CODE should be enough to set
       # -fPIC for GCC but sometimes it still doesn't get set, so make sure it
       # does.
       add_definitions("-fPIC")
    endif()
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif(BUILD_SHARED_LIBS)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
include(GenerateExportHeader)
include(CheckIncludeFile)
include(CheckIncludeFileCXX)
include(CheckFunctionExists)

# Create will be delete files
CONFIGURE_FILE(
    "${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
# Create unistall target
ADD_CUSTOM_TARGET(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
    )

add_subdirectory(src)

CONFIGURE_FILE(
    "${CMAKE_SOURCE_DIR}/cmake/coturnConfig.cmake.in"
    "${CMAKE_BINARY_DIR}/coturnConfig.cmake"
    IMMEDIATE @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/coturnConfig.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/coturn"
        COMPONENT Development)

install(DIRECTORY man DESTINATION .
    COMPONENT Runtime)
install(DIRECTORY turndb/
    DESTINATION share/turnserver
        COMPONENT Runtime)
install(DIRECTORY turndb/
    DESTINATION doc/turnserver
        COMPONENT Runtime)
install(FILES
            LICENSE
            README.turnserver
            README.turnadmin
            README.turnutils
            INSTALL
            postinstall.txt
        DESTINATION doc/turnserver
            COMPONENT Runtime)
install(FILES examples/etc/turnserver.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
        COMPONENT Runtime
    RENAME turnserver.conf.default
    )
install(DIRECTORY
        examples
    DESTINATION share
        COMPONENT examples
    )
include(cmake/CMakeCPack.cmake)

option(FUZZER "Build oss-fuzz fuzzing" OFF)
if(FUZZER)
    if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "clang is require for libFuzzer")
    endif()

    add_subdirectory(fuzzing)

endif()
