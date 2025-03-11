#include <openssl/sha.h>
#include <stdio.h>

void sha256_hash(const char *input, unsigned char *output) {
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, input, strlen(input));
    SHA256_Final(output, &sha256_ctx);
}

int main() {
    const char *input = "Hello, SHA-256!";
    unsigned char hash[SHA256_DIGEST_LENGTH];

    sha256_hash(input, hash);

    printf("SHA-256 Hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
