// Copyright (C) 2015 the Massachusetts Institute of Technology
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations under
// the License.

#ifndef URWEB_CRYPTO_HASH_OPENSSL_HASHFFI_H
#define URWEB_CRYPTO_HASH_OPENSSL_HASHFFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <urweb/urweb_cpp.h>

uw_Basis_string uw_HashFFI_md5(struct uw_context*, const uw_Basis_blob);
uw_Basis_string uw_HashFFI_sha1(struct uw_context*, const uw_Basis_blob);

#ifdef __cplusplus
}
#endif

#endif  // URWEB_CRYPTO_HASH_OPENSSL_HASHFFI_H
