
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "client_bindings.h"


int main(int argc, char *argv[]) {
  char message[6];
  strcpy(message, "hello");
  int i;
  Register(argv[1]);
  NewClient("echo");
  NewSession();
  GetService("echo");
  struct BlockingSendUnreliableMessage_return r = BlockingSendUnreliableMessage(message, strlen(message));
  
  printf("packet_len: %zu \n",r.r1);
  for ( i = 0; i < r.r1; i++ )
    {
        printf("%c",r.r0[i]);
    }
  Shutdown();

  return 0;
}