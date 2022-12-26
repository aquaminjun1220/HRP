#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <string.h>


int main()
{
  uint8_t buf[160];
  memset(buf, 'A', 160);
  while(1)
  {
    if (write(1, buf, 160) < 0)
      perror("ERROR: write");
  }
}