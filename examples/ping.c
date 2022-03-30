
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "client_bindings.h"


int main(int argc, char *argv[]) {
  char ticker[3];
//   strcpy(ticker, "gor");
  char message[50];
  strcpy(message, "hello!");
  

  Register(argv[1]);
  NewClient("loop");
  NewSession();
  GetService("loop");
  BlockingSendUnreliableMessage(message, strlen(message));
  Shutdown();


  return 0;
}