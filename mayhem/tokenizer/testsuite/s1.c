#include <stdio.h>
#define X(a) (a##1 + 0x1fULL)
int main(void) { const char *s = "a\"b\n"; float f = 1.5e-3f; char c = L'x'; return s[0] >> 2; /* c */ }
