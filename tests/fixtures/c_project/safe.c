#include <stdio.h>
#include <string.h>

#define MAX_LEN 64

void safe_copy(const char *input, size_t input_len) {
    char buffer[MAX_LEN];
    size_t copy_len = input_len < MAX_LEN - 1 ? input_len : MAX_LEN - 1;
    memcpy(buffer, input, copy_len);
    buffer[copy_len] = '\0';
    printf("Safe: %s\n", buffer);
}
