#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

void generate_rsa_keys() {
    RSA *r = RSA_generate_key(2048, RSA_F4, NULL, NULL);  // Generate RSA key pair
    FILE *priv_key_file = fopen("private.pem", "wb");
    FILE *pub_key_file = fopen("public.pem", "wb");

    // Write private and public keys to files
    PEM_write_RSAPrivateKey(priv_key_file, r, NULL, NULL, 0, NULL, NULL);
    PEM_write_RSA_PUBKEY(pub_key_file, r);

    fclose(priv_key_file);
    fclose(pub_key_file);
    RSA_free(r);
}

void rsa_encrypt_decrypt_example() {
    FILE *pub_key_file = fopen("public.pem", "rb");
    FILE *priv_key_file = fopen("private.pem", "rb");

    RSA *public_key = PEM_read_RSA_PUBKEY(pub_key_file, NULL, NULL, NULL);
    RSA *private_key = PEM_read_RSAPrivateKey(priv_key_file, NULL, NULL, NULL);

    unsigned char input[] = "Hello, RSA!";
    unsigned char encrypted[256];
    unsigned char decrypted[256];

    // Encrypt with public key
    int encrypted_length = RSA_public_encrypt(strlen((char *)input) + 1, input, encrypted, public_key, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        ERR_print_errors_fp(stderr);
        return;
    }

    printf("Encrypted message: ");
    for (int i = 0; i < encrypted_length; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    // Decrypt with private key
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        ERR_print_errors_fp(stderr);
        return;
    }

    printf("Decrypted message: %s\n", decrypted);

    fclose(pub_key_file);
    fclose(priv_key_file);
    RSA_free(public_key);
    RSA_free(private_key);
}

int main() {
    generate_rsa_keys();  // Generate RSA keys
    rsa_encrypt_decrypt_example();  // RSA encryption and decryption example
    return 0;
}
