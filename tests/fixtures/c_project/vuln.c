#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 64

void parse_header(const char *input, size_t input_len) {
    char buffer[BUFFER_SIZE];
    /* Buffer overflow: memcpy with attacker-controlled size */
    memcpy(buffer, input, input_len);
    printf("Header: %s\n", buffer);
}

void process_data(const char *data) {
    char *buf = malloc(128);
    strcpy(buf, data);  /* Potential buffer overflow with strcpy */
    printf("Data: %s\n", buf);
    free(buf);
    /* Use after free */
    printf("Freed data: %s\n", buf);
}

int compute_size(int count, int element_size) {
    /* Integer overflow before allocation */
    int total = count * element_size;
    char *buffer = malloc(total);
    if (buffer) {
        memset(buffer, 0, total);
        free(buffer);
    }
    return total;
}

void log_message(const char *user_input) {
    /* Format string vulnerability */
    printf(user_input);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        parse_header(argv[1], strlen(argv[1]));
        process_data(argv[1]);
        log_message(argv[1]);
    }
    return 0;
}
