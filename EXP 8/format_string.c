#include <stdio.h>

void vulnerable_function(char *user_input) {
    // Unsafe use of user input directly in printf
    printf(user_input);
}

int main() {
    char input[100];
    printf("Enter your input: ");
    fgets(input, sizeof(input), stdin);  // Read user input
    vulnerable_function(input);  // Pass user input to printf
    return 0;
}
