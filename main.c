#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>

typedef int8_t   i8;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)


// Must be seeded with a nonzero value.
// Accessible from the outside so we can modify it
u64 random_state = 12345;

// Pseudo-random 64 bit number, based on xorshift*
u64 rand64()
{
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * 0x2545F4914F6CDD1D; // magic constant
}

void p_random(u8 *stream, size_t size)
{
    FOR (i, 0, size) {
        stream[i] = (u8)rand64();
    }
}

void print_vector(const u8 *buf, size_t size)
{
    FOR (i, 0, size) {
        printf("%x%x", buf[i] >> 4, buf[i] & 0x0f);
    }
    printf(":\n");
}


int main(void) {
    RANDOM_INPUT(message, 32);
    print_vector(message, 32);
}
