
#include <string.h>

extern char gS[]; 
extern char gBadBuf[]; 
extern void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
void antiasan(unsigned long addr) {
    __asan_unpoison_memory_region(gS, 0xa7);
    __asan_unpoison_memory_region(gBadBuf, 0xa7);
}
