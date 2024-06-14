#ifndef HOOK_H

#define HOOK_H

#include <Windows.h>

unsigned int splice(unsigned char* addr, void* hook_fn);

#endif