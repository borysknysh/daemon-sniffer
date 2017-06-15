#include "shell.h"

int main()
{
  initCLI();
  lsh_loop();
  return 0;
}