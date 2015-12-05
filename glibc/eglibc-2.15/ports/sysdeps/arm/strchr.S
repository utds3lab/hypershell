        .syntax unified
        .arch armv7-a

@ Copyright (c) 2010-2011, Linaro Limited
@ All rights reserved.

@ Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

@    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
@    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
@    * Neither the name of Linaro Limited nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

@ THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@ Written by Dave Gilbert <david.gilbert@linaro.org>

@ A very simple strchr routine, from benchmarks on A9 it's a bit faster than the
@ current version in eglibc (2.12.1-0ubuntu14 package)
@ I don't think doing a word at a time version is worth it since a lot
@ of strchr cases are very short anyway

@ 2011-02-07 david.gilbert@linaro.org
@    Extracted from local git a5b438d861

@ 2011-02-11 david.gilbert@linaro.org
@    Imported into eglibc build from cortex-strings bzr rev 17, fixed up entry/exit/includes
@    to match the eglibc way of doing things

@ 2011-02-22 david.gilbert@linaro.org
@    Added weak alias for index
@
@ 2011-09-07 david.gilbert@linaro.org
@    Mask r1 input to strchr as per lp:842258

@ TODO: Prior to upstreaming we need to add fallbacks for older CPUs

#include <sysdep.h>

	.text
	.thumb

@ ---------------------------------------------------------------------------

        .thumb_func
        .align 2
        .p2align 4,,15
        .global strchr
        .type strchr,%function
ENTRY(strchr)
  @ r0 = start of string
  @ r1 = character to match
  @ returns NULL for no match, or a pointer to the match

  and      r1,r1,#255   @ C standard requires us to turn it into char
1:
  ldrb     r2,[r0],#1
  cmp      r2,r1
  cbz      r2,10f
  bne      1b

  @ We're here if it matched
5:
  subs     r0,r0,#1
  DO_RET(lr)

10:
  @ We're here if we ran off the end
  cmp      r1, #0        @ Corner case - you're allowed to search for the nil and get a pointer to it
  beq      5b            @ A bit messy, if it's common we should branch at the start to a special loop
  mov      r0,#0
  DO_RET(lr)

END(strchr)

weak_alias (strchr, index)
libc_hidden_builtin_def(strchr)
