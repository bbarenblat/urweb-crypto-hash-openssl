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

#include "hashFFI.h"

#include <array>
#include <cstdio>
#include <functional>

#include <openssl/md5.h>
#include <openssl/sha.h>
extern "C" {
#include <urweb/urweb_cpp.h>
}

static_assert(sizeof(char) == 1, "char is not a single byte");
static_assert(sizeof(unsigned char) == 1, "unsigned char is not a single byte");

namespace {

using OpenSSLHashFunction =
    std::function<unsigned char*(const unsigned char*, std::size_t,
                                 unsigned char*)>;

// Asserts a condition without crashing or releasing information about where the
// error occurred.  This function is essential for web programming, where an
// attacker should not be able to bring down the app by causing an assertion
// failure.
void Assert(uw_context* const context, const bool condition,
            const failure_kind action, const char* const message) {
  if (!condition) {
    uw_error(context, action, message);
  }
}

void Assert(uw_context* const context,
            const bool condition, const char* const message) {
  Assert(context, condition, FATAL, message);
}

template<std::size_t digest_length>
uw_Basis_string Hash(uw_context* const context, const uw_Basis_blob input,
                     OpenSSLHashFunction hash) {
  using Digest = std::array<unsigned char, digest_length>;
  // Perform the hash operation.
  Digest raw_result;
  hash(reinterpret_cast<unsigned char*>(input.data), input.size,
       raw_result.data());
  // Convert it to a hex string.  This will be twice as large (two hex digits
  // per byte), plus an additional byte for the null terminator.
  const auto result_length = 2 * raw_result.size() + 1;
  uw_Basis_string result =
      reinterpret_cast<uw_Basis_string>(uw_malloc(context, result_length));
  Assert(context, result, BOUNDED_RETRY,
         "unable to allocate memory for digest");
  for (typename Digest::size_type i = 0; i < raw_result.size(); i++) {
    sprintf(result + 2 * i, "%02x", raw_result[i]);
  }
  // Make sure the string is properly terminated.
  for (std::size_t i = 0; i < result_length - 2; i++) {
    Assert(context, result[i] != '\0', "null byte in digest");
  }
  Assert(context, result[result_length - 1] == '\0',
         "failed to properly terminate digest");
  return result;
}

}  // namespace

uw_Basis_string uw_HashFFI_md5(uw_context* const context,
                               const uw_Basis_blob input) {
  return Hash<MD5_DIGEST_LENGTH>(context, input, MD5);
}

uw_Basis_string uw_HashFFI_sha1(uw_context* const context,
                               const uw_Basis_blob input) {
  return Hash<SHA_DIGEST_LENGTH>(context, input, SHA1);
}

uw_Basis_string uw_HashFFI_sha224(uw_context* const context,
                                  const uw_Basis_blob input) {
  return Hash<SHA224_DIGEST_LENGTH>(context, input, SHA224);
}

uw_Basis_string uw_HashFFI_sha256(uw_context* const context,
                                  const uw_Basis_blob input) {
  return Hash<SHA256_DIGEST_LENGTH>(context, input, SHA256);
}

uw_Basis_string uw_HashFFI_sha384(uw_context* const context,
                                  const uw_Basis_blob input) {
  return Hash<SHA384_DIGEST_LENGTH>(context, input, SHA384);
}

uw_Basis_string uw_HashFFI_sha512(uw_context* const context,
                                  const uw_Basis_blob input) {
  return Hash<SHA512_DIGEST_LENGTH>(context, input, SHA512);
}
