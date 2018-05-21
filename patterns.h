#ifndef _SIDER_PATTERNS_H
#define _SIDER_PATTERNS_H

// code patterns to search

static BYTE lcpk_pattern_at_read_file[23] =
    "\x48\x8b\x0b"
    "\x48\x83\x64\x24\x20\x00"
    "\x4c\x8d\x4c\x24\x60"
    "\x41\x89\xf8"
    "\x48\x89\xf2"
    "\xff\x15";
static int lcpk_offs_at_read_file = 20;

static BYTE lcpk_pattern_at_alloc_mem[19] =
    "\x48\x89\x44\xdf\x18"
    "\x48\x63\x8f\x54\x02\x00\x00"
    "\x48\x8b\xd0"
    "\x8d\x41\xff";
static int lcpk_offs_at_alloc_mem = -5;

#endif

