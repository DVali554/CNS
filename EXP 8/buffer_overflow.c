#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[256];
    strcpy(buffer, input);  // No bounds checking
}

int main() {
    char *input = "A very long string that exceeds the buffer size...";
    vulnerable_function(input);
    return 0;
}
