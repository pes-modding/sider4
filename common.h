#ifndef SIDER_COMMON_H
#define SIDER_COMMON_H

#include "windows.h"

BYTE* find_code_frag(BYTE*, LONGLONG, BYTE*, size_t);
BYTE* get_target_addr(BYTE* call_location);
void hook_call_point(DWORD addr, void* func, int codeShift, int numNops, bool addRetn=false);

#endif
