/* Support for reading /etc/ld.so.cache files written by Linux ldconfig.
   Copyright (C) 2011 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Steve McIntyre <steve.mcintyre@linaro.org>

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <ldconfig.h>

/* Redefine the cache ID for the new hf ABI; the sf ABI inverts the check.  */
#define _DL_CACHE_ARMHF_ID  (FLAG_ARM_HFABI | FLAG_ELF_LIBC6)

#ifdef __ARM_PCS_VFP
#define _dl_cache_check_flags(flags) \
  ((flags) == _DL_CACHE_ARMHF_ID)
#else
#define _dl_cache_check_flags(flags) \
  ((flags) != _DL_CACHE_ARMHF_ID)
#endif

#include_next <dl-cache.h>
