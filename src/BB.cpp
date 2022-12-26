#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <string>

int main()
{
    int n = 0;
    while (1)
    {
        uint8_t buffer[2048];
        n += read(0, buffer, 2048);
        std::cout << n << std::endl;
    }
}