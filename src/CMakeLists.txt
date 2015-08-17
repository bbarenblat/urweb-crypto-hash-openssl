# Copyright 2015 the Massachusetts Institute of Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

add_library(urweb_crypto_hash_openssl
  hashFFI.cc
)

set_target_properties(urweb_crypto_hash_openssl PROPERTIES
  VERSION 0.0.0
  SOVERSION 0
)

find_path(URWEB_INCLUDE_DIR NAMES urweb/urweb_cpp.h)
include_directories(${URWEB_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

target_link_libraries(urweb_crypto_hash_openssl
  ${OPENSSL_CRYPTO_LIBRARY}
)

install(TARGETS urweb_crypto_hash_openssl
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)
install(
  FILES
    hashFFI.h
    hashFFI.urs
    hash.ur
    hash.urs
    lib.urp
  DESTINATION share/urweb/ur/crypto-hash-openssl
)
