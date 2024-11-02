#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MAX_ALTERNATES 16
#define MAX_MATCHES 256
#define NOP 0x90

const char *MSEAL_PATTERN = "48 c7 c0 ce 01 00 00 48|4c 89 ?? 48|4c 89 ?? 48|4c 89 ?? 0f 05";

const unsigned char REPLACEMENT[] = { 
    0x48, 0x31, 0xC0, // xor rax, rax
    0x48, 0x31, 0xFF, // xor rdi, rdi
    0x48, 0x31, 0xF6, // xor rsi, rsi
    0x48, 0x31, 0xD2  // xor rdx, rdx
};

typedef struct {
    unsigned char byte;
    bool is_wildcard;
    unsigned char alternates[MAX_ALTERNATES];
    size_t num_alternates;
} PatternByte;

typedef struct {
    void *matches[MAX_MATCHES];
    size_t count;
} PatternMatches;

unsigned char hex_to_byte(const char *hex) {
    int value;
    sscanf(hex, "%2x", &value);
    return (unsigned char)value;
}

size_t parse_pattern(const char *pattern, PatternByte *bytes) {
    size_t count = 0;
    char hex[3] = {0};
    const char *ptr = pattern;
    
    while (*ptr) {
        while (isspace(*ptr))
            ptr++;
        if (!*ptr)
            break;

        // Handle wildcard(s)
        if (*ptr == '?') {
            bytes[count].is_wildcard = true;
            bytes[count].num_alternates = 0;
            count++;
            ptr++;
            
            // Check for second '?' 
            if (*ptr == '?') {
                bytes[count].is_wildcard = true;
                bytes[count].num_alternates = 0;
                ptr++;
            }
            continue;
        }
        
        // Parse first byte
        if (!isxdigit(ptr[0]) || !isxdigit(ptr[1])) {
            printf("Invalid hex digit at position %td\n", ptr - pattern);
            return 0;
        }
        
        hex[0] = ptr[0];
        hex[1] = ptr[1];
        bytes[count].byte = hex_to_byte(hex);
        bytes[count].is_wildcard = false;
        bytes[count].num_alternates = 0;
        ptr += 2;
        
        // Check for alternates
        while (1) {
            while (isspace(*ptr))
                ptr++;
            if (*ptr != '|')
                break;
            
            ptr++;
            while (isspace(*ptr))
                ptr++;
            
            if (!isxdigit(ptr[0]) || !isxdigit(ptr[1])) {
                printf("Invalid alternate hex digit\n");
                return 0;
            }
            
            hex[0] = ptr[0];
            hex[1] = ptr[1];
            
            if (bytes[count].num_alternates >= MAX_ALTERNATES) {
                printf("Too many alternates for byte at position %zu\n", count);
                return 0;
            }
            
            bytes[count].alternates[bytes[count].num_alternates++] = hex_to_byte(hex);
            ptr += 2;
        }
        
        count++;
    }
    return count;
}

void *find_pattern(void *start, size_t length, const char *pattern, size_t *pattern_length) {
    PatternByte bytes[256] = {0};
    *pattern_length = parse_pattern(pattern, bytes);
    
    if (*pattern_length == 0)
        return NULL;
    
    unsigned char *current = (unsigned char *)start;
    unsigned char *end = current + length - *pattern_length;
    
    while (current <= end) {
        bool found = true;
        
        for (size_t i = 0; i < *pattern_length && found; i++) {
            if (bytes[i].is_wildcard)
                continue;

            bool byte_match = (current[i] == bytes[i].byte);
            
            // Check alternates if main byte didn't match
            if (!byte_match) {
                byte_match = false;
                for (size_t j = 0; j < bytes[i].num_alternates; j++) {
                    if (current[i] == bytes[i].alternates[j]) {
                        byte_match = true;
                        break;
                    }
                }
            }
            
            if (!byte_match)
                found = false;
        }
        
        if (found)
            return current;
        current++;
    }
    
    return NULL;
}

void find_all_patterns(void *start, size_t length, const char *pattern, size_t *pattern_length, PatternMatches *results) {
    PatternByte bytes[256] = {0};
    *pattern_length = parse_pattern(pattern, bytes);
    results->count = 0;
    
    if (*pattern_length == 0)
        return;
    
    unsigned char *current = (unsigned char *)start;
    unsigned char *end = current + length - *pattern_length;
    
    while (current <= end) {
        bool found = true;
        
        for (size_t i = 0; i < *pattern_length && found; i++) {
            if (bytes[i].is_wildcard)
                continue;

            bool byte_match = (current[i] == bytes[i].byte);
            
            if (!byte_match) {
                for (size_t j = 0; j < bytes[i].num_alternates; j++) {
                    if (current[i] == bytes[i].alternates[j]) {
                        byte_match = true;
                        break;
                    }
                }
            }
            
            if (!byte_match)
                found = false;
        }
        
        if (found && results->count < MAX_MATCHES)
            results->matches[results->count++] = current;
        current++;
    }
}

void replace_pattern(PatternMatches *results, size_t pattern_length, 
                    const unsigned char *REPLACEMENT, size_t replacement_length) {
    
    for (size_t i = 0; i < results->count; i++) {
        unsigned char *target = (unsigned char*)results->matches[i];
        
        memcpy(target, REPLACEMENT, replacement_length);
        
        if (replacement_length < pattern_length) {
            memset(target + replacement_length, NOP, pattern_length - replacement_length);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("open input");
        return 1;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    unsigned char *test_data = malloc(size);
    if (!test_data) {
        perror("malloc");
        close(fd);
        return 1;
    }

    if (read(fd, test_data, size) != size) {
        perror("read");
        free(test_data);
        close(fd);
        return 1;
    }
    close(fd);

    char output_file[256];
    // remove all the path before the filename
    char *filename = strrchr(argv[1], '/');
    if (filename)
        snprintf(output_file, sizeof(output_file), "patched_%s", filename + 1);
    else
        snprintf(output_file, sizeof(output_file), "patched_%s", argv[1]);

    size_t pattern_length = 0;
    PatternMatches results = {0};
    

    size_t replacement_length = sizeof(REPLACEMENT);

    find_all_patterns(test_data, size, MSEAL_PATTERN, &pattern_length, &results);
    
    printf("Found %zu matches in %s\n", results.count, argv[1]);
    for (size_t i = 0; i < results.count; i++) {
        printf("Match %zu at offset: %td\n", i + 1, 
               (unsigned char*)results.matches[i] - test_data);
    }
    
    replace_pattern(&results, pattern_length, REPLACEMENT, replacement_length);

    int out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd == -1) {
        perror("open output");
        free(test_data);
        return 1;
    }

    if (write(out_fd, test_data, size) != size) {
        perror("write");
        free(test_data);
        close(out_fd);
        return 1;
    }

    close(out_fd);
    free(test_data);

    printf("Patched elf saved as : ./%s\n", output_file);
    return 0;
}
