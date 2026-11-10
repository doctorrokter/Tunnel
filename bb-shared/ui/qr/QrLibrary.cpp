/*
 * bb-shared / ui / qr / QrLibrary.cpp - Nayuki's qrcodegen.c (MIT, the file as it comes) compiled as C++. As
 * a .c file it would ask every app for C99 (the NDK's gcc takes a .c as C89: -Wc,-std=gnu99) and for no
 * precompiled header (a C file cannot take the app's C++ one); as C++ it asks for nothing. Its names stay C
 * (qrcodegen.h's extern "C"): an app with a copy of qrcodegen of its own deletes it when it turns
 * bb_shared_qr on, or the two link twice.
 */
#include <stddef.h>
#include <stdint.h>

// C++ before C++11 gets <stdint.h>'s limits only with __STDC_LIMIT_MACROS defined before its FIRST include,
// and the app's precompiled header may have made that include already (the NDK's gcc 4.6: "'INT16_MAX' was
// not declared"). The two qrcodegen.c uses, in code only:
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) -1)
#endif
#ifndef INT16_MAX
#define INT16_MAX 32767
#endif

#include "qrcodegen.c"
