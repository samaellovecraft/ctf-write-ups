#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"
#define AUTH_KEY_PART "UHI75GHI"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}

int main() {
    char auth_key[13];
    strcpy(auth_key, AUTH_KEY_PART);

    char md5_suffix[5] = "";
    for (char c1 = '0'; c1 <= 'f'; c1++) {
        for (char c2 = '0'; c2 <= 'f'; c2++) {
            for (char c3 = '0'; c3 <= 'f'; c3++) {
                for (char c4 = '0'; c4 <= 'f'; c4++) {
                    sprintf(md5_suffix, "%c%c%c%c", c1, c2, c3, c4);
                    strcat(auth_key, md5_suffix);

                    if (check_auth(auth_key)) {
                        printf("auth_key: %s\n", auth_key);
                        return 0;
                    }
                    // reset partial key for next combination
                    auth_key[strlen(AUTH_KEY_PART)] = '\0';
                }
            }
        }
    }
    puts("auth_key not found.");
    return 1;
}
