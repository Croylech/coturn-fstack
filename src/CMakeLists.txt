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

include_directories(
  ${CMAKE_SOURCE_DIR}/src/Fstack
  /usr/local/include
)

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(apps)


if(USE_FSTACK)
    add_compile_definitions(USE_FSTACK)
endif()

# Añadir wrappers.c manualmente
set(WRAPPERS_SRC ${CMAKE_CURRENT_SOURCE_DIR}/Fstack/wrappers.c)
add_library(fstack_wrappers STATIC ${WRAPPERS_SRC})

# Busca DPDK con pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# Incluir headers
target_include_directories(fstack_wrappers PRIVATE
    ${DPDK_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/Fstack
    ${CMAKE_SOURCE_DIR}/f-stack/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/apps/relay
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/src/apps/common
)

# Definiciones de compilación
#target_compile_definitions(fstack_wrappers PRIVATE USE_FSTACK)

# Enlazar correctamente: F-Stack + DPDK + otras dependencias
target_link_libraries(fstack_wrappers
    ${CMAKE_SOURCE_DIR}/f-stack/lib/libfstack.a
    ${DPDK_LIBRARIES}
    -lrte_net_bond
    pthread
    numa
    dl
)

# Exportación correcta
install(TARGETS fstack_wrappers EXPORT coturnTargets)

install(EXPORT coturnTargets
  FILE coturnTargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/coturn
)