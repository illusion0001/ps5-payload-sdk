/* Copyright (C) 2023 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>

#include "mdbg.h"
#include "patch.h"
#include "pt.h"

#define MAX_HEX_DUMP_BYTES 2048

// https://github.com/Cryptogenic/PS5-SELF-Decrypter/blob/def326f36c1f1b461030222daa9ea6124d4ce610/source/sbl.c#L25
void hex_dump(const void *data, size_t size)
{
  if (size >= MAX_HEX_DUMP_BYTES)
    return;
  char hexbuf[MAX_HEX_DUMP_BYTES] = {0};
  char *cur = hexbuf;
#undef MAX_HEX_DUMP_BYTES
  sprintf(cur, "hex:\n");
  cur += strlen(cur);

  char ascii[17] = {0};
  size_t i, j;
  for (i = 0; i < size; ++i)
  {
    sprintf(cur, "%02X ", ((unsigned char *)data)[i]);
    cur += strlen(cur);

    if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
    {
      ascii[i % 16] = ((unsigned char *)data)[i];
    }
    else
    {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size)
    {
      sprintf(cur, " ");
      cur += strlen(cur);

      if ((i + 1) % 16 == 0)
      {
        sprintf(cur, "|  %s \n", ascii);
        cur += strlen(cur);
      }
      else if (i + 1 == size)
      {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8)
        {
          sprintf(cur, " ");
          cur += strlen(cur);
        }
        for (j = (i + 1) % 16; j < 16; ++j)
        {
          sprintf(cur, "   ");
          cur += strlen(cur);
        }
        sprintf(cur, "|  %s \n", ascii);
        cur += strlen(cur);
      }
    }
  }
  puts(hexbuf);
}

int
patch_app(pid_t pid, uint32_t app_id, const char* title_id) {
  struct ptrace_vm_entry ve;
  uint8_t *buf;
  size_t len;

  printf("New application launched:\n"
	 "------------------------\n"
	 "  title_id = %s\n"
	 "  app_id = 0x%x\n"
	 "  pid = %d\n",
	 title_id, app_id, pid);

  // TODO: something useful. For now, just sanity test mdbg
  memset(&ve, 0, sizeof(ve));
  if(pt_vm_entry(pid, &ve)) {
    return -1;
  }

  len = ve.pve_end - ve.pve_start;
  if(!(buf=malloc(len))){
    return -1;
  }

  printf("  vm entry 0 starts at: 0x%lx ends at: 0x%lx size of vm 0x%lx bytes\n", ve.pve_start, ve.pve_end, len);

  if(mdbg_copyout(pid, ve.pve_start, buf, len)) {
    perror("mdbg_copyout");
    free(buf);
    return -1;
  }
  hex_dump(buf, 32);

  if(mdbg_copyin(pid, buf, ve.pve_start, len)) {
    perror("mdbg_copyin");
    free(buf);
    return -1;
  }

  free(buf);

  return 0;
}
