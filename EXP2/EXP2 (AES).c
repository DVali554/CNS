//EXPERIMENT 02 : AES ALGORITHM
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>

void encrypt_decrypt_aes(const unsigned char *input, unsigned char *output, const unsigned char *key, int encrypt) {
    AES_KEY aes_key;
    unsigned char iv[AES_BLOCK_SIZE] = {0};  // Initialization Vector (IV)

    // Set the encryption or decryption key
    if (encrypt) {
        AES_set_encrypt_key(key, 128, &aes_key);  // Set the key for encryption
    } else {
        AES_set_decrypt_key(key, 128, &aes_key);  // Set the key for decryption
    }

    // Encrypt or decrypt the input
    AES_cbc_encrypt(input, output, strlen((char *)input), &aes_key, iv, encrypt ? AES_ENCRYPT : AES_DECRYPT);
}

int main() {
    unsigned char key[16] = "1234567890abcdef";  // 16-byte key for AES-128
    unsigned char input[32] = "This is a test message!";
    unsigned char encrypted[32];
    unsigned char decrypted[32];

    printf("Input: %s\n", input);

    // Encrypt
    encrypt_decrypt_aes(input, encrypted, key, 1);
    printf("Encrypted: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    // Decrypt
    encrypt_decrypt_aes(encrypted, decrypted, key, 0);
    printf("Decrypted: %s\n", decrypted);

    return 0;
}
