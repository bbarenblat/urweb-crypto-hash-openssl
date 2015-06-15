(* Copyright 2015 the Massachusetts Institute of Technology

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.  You may obtain a copy of the
License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License. *)

type digest
val eq_digest : eq digest
val ord_digest : ord digest
val show_digest : show digest
val sql_digest : sql_injectable digest
val sql_maxable_digest : sql_maxable digest

val md5 : blob -> digest

val sha1 : blob -> digest
