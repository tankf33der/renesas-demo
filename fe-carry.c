#include <stdint.h>
#include <stddef.h>

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(i, 0, size) (dst)[i] = (src)[i]

typedef int32_t  i32;
typedef uint64_t u64;
typedef int64_t  i64;
typedef i32 fe[10];

static void fe_carry(fe h, i64 t[10])
{
    i64 c;
    for (size_t i = 0; i < 4; i += 2) {
        c = (t[i+0]+((i64)1<<25))>>26; t[i+1] += c; t[i+0] -= c*((i64)1 << 26);
        c = (t[i+4]+((i64)1<<25))>>26; t[i+5] += c; t[i+4] -= c*((i64)1 << 26);
        c = (t[i+1]+((i64)1<<24))>>25; t[i+2] += c; t[i+1] -= c*((i64)1 << 25);
        c = (t[i+5]+((i64)1<<24))>>25; t[i+6] += c; t[i+5] -= c*((i64)1 << 25);
    }
    c = (t[4] + ((i64)1<<25)) >> 26; t[5] += c;      t[4] -= c * ((i64)1 << 26);
    c = (t[8] + ((i64)1<<25)) >> 26; t[9] += c;      t[8] -= c * ((i64)1 << 26);
    c = (t[9] + ((i64)1<<24)) >> 25; t[0] += c * 19; t[9] -= c * ((i64)1 << 25);
    c = (t[0] + ((i64)1<<25)) >> 26; t[1] += c;      t[0] -= c * ((i64)1 << 26);
    COPY(h, t, 10);
}

