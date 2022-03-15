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

static BYTE lcpk_pattern_at_get_size[25] =
    "\xeb\x05"
    "\xe8\x7b\xf3\xff\xff"
    "\x85\xc0"
    "\x74\x24"
    "\x8b\x44\x24\x34"
    "\x89\x43\x04"
    "\x8b\x44\x24\x30"
    "\x89\x03";
static int lcpk_offs_at_get_size = 24;

static BYTE lcpk_pattern_at_write_cpk_filesize[16] =
    "\x48\x8b\x44\x24\x48"
    "\x48\x89\x47\x08"
    "\x49\x89\x7d\x00"
    "\x33\xc0";
static int lcpk_offs_at_write_cpk_filesize = 0;

static BYTE lcpk_pattern_at_mem_copy[13] =
    "\x4c\x8b\x01"
    "\x4c\x8b\xcb"
    "\x49\x8b\xcb"
    "\x4d\x03\xc2";
static int lcpk_offs_at_mem_copy = 9;

static BYTE lcpk_pattern_at_lookup_file[16] =
    "\x48\x8d\x8f\x10\x01\x00\x00"
    "\x4c\x8b\xc6"
    "\x48\x8d\x54\x24\x20";
static int lcpk_offs_at_lookup_file = 0;

/*
000000014126DF00 | 49 63 00                           | movsxd rax,dword ptr ds:[r8]            | prep to write team info
000000014126DF03 | 83 F8 02                           | cmp eax,2                               |
000000014126DF06 | 7D 16                              | jge pes2018.14126DF1E                   |
000000014126DF08 | 4C 69 C0 20 05 00 00               | imul r8,rax,520                         |
000000014126DF0F | 48 81 C1 04 01 00 00               | add rcx,104                             |
000000014126DF16 | 49 03 C8                           | add rcx,r8                              |
*/
static BYTE pattern_set_team_id[26] =
    "\x49\x63\x00"
    "\x83\xf8\x02"
    "\x7d\x16"
    "\x4c\x69\xc0\x20\x05\x00\x00"
    "\x48\x81\xc1\x04\x01\x00\x00"
    "\x49\x03\xc8";
static int offs_set_team_id = 0;

/*
000000014126DF0C | 83 F8 02                           | cmp eax,2                               |
000000014126DF0F | 7D 0D                              | jge pes2018.14126DF1E                   |
000000014126DF11 | 90                                 | nop                                     |
000000014126DF12 | 90                                 | nop                                     |
000000014126DF13 | 90                                 | nop                                     |
000000014126DF14 | 90                                 | nop                                     |
000000014126DF15 | 90                                 | nop                                     |
000000014126DF16 | 90                                 | nop                                     |
000000014126DF17 | 90                                 | nop                                     |
000000014126DF18 | 90                                 | nop                                     |
*/
static BYTE pattern_set_team_id_tail[14] =
    "\x83\xf8\x02"
    "\x7d\x0d"
    "\x90\x90\x90\x90\x90\x90\x90\x90";

/*
00000001412A4FD5 | 0F B6 82 8B 00 00 00               | movzx eax,byte ptr ds:[rdx+8B]          |
00000001412A4FDC | 88 81 8B 00 00 00                  | mov byte ptr ds:[rcx+8B],al             |
00000001412A4FE2 | 48 8B C1                           | mov rax,rcx                             |
00000001412A4FE5 | C3                                 | ret                                     |
*/
static BYTE pattern_set_settings[18] =
    "\x0f\xb6\x82\x8b\x00\x00\x00"
    "\x88\x81\x8b\x00\x00\x00"
    "\x48\x8b\xc1"
    "\xc3";
static int offs_set_settings = 0;

/*
0000000141C5A870 | 0F B7 D0                           | movzx edx,ax                            | check tournament_id for trophy
0000000141C5A873 | 66 89 44 24 50                     | mov word ptr ss:[rsp+50],ax             |
0000000141C5A878 | 48 8B CD                           | mov rcx,rbp                             |
static BYTE pattern_trophy_check[12] =
    "\x0f\xb7\xd0"
    "\x66\x89\x44\x24\x50"
    "\x48\x8b\xcd";
static int offs_trophy_check = -12;
*/

static BYTE pattern_trophy_check[20] =
    "\x48\x89\x5c\x24\x10"
    "\x57"
    "\x48\x83\xec\x20"
    "\x48\x8b\xda"
    "\x0f\xb7\xf9"
    "\x48\x85\xd2";
static int offs_trophy_check = 5;

static BYTE pattern_trophy_check_head[5] =
    "\x48\x83\xec\x28";

static BYTE pattern_trophy_check_tail[10] =
    "\x48\x85\xd2"
    "\x0f\x84\x8d\x00\x00\x00";


/*
0000000140A0DF3C | 48 89 8B 84 00 00 00                 | mov qword ptr ds:[rbx+84],rcx           |
0000000140A0DF43 | 48 C7 83 AC 59 01 00 FF FF FF FF     | mov qword ptr ds:[rbx+159AC],FFFFFFFFFF |
*/
static BYTE pattern_context_reset[19] =
    "\x48\x89\x8b\x84\x00\x00\x00"
    "\x48\xc7\x83\xac\x59\x01\x00\xff\xff\xff\xff";
static int offs_context_reset = 0;

// controller restrictions ("sider")

static BYTE pattern_sider_1[16] =
    "\x8b\x75\x58"
    "\x44\x0f\xb6\x65\x68"
    "\x4c\x8b\x7d\x48"
    "\xc6\x03\x04";
static int offs_sider_1 = 14;
static BYTE patch_sider_1[2] = "\0";

static BYTE pattern_sider_2[16] =
    "\x8b\x75\x58"
    "\x4c\x8b\x7d\x48"
    "\x44\x0f\xb6\x65\x68"
    "\xc6\x03\x02";
static int offs_sider_2 = 14;
static BYTE patch_sider_2[2] = "\0";

static BYTE pattern_sider_3[20] =
    "\x83\xbf\x50\x04\x00\x00\x02"
    "\xb8\x04\x00\x00\x00"
    "\x44\x0f\x45\xf8"
    "\x44\x88\x3b";
static int offs_sider_3 = 8;
static BYTE patch_sider_3[2] = "\0";

static BYTE pattern_sider_4[10] =
    "\xf7\xd8"
    "\x1a\xc9"
    "\x80\xe1\x02"
    "\x88\x0b";
static int offs_sider_4 = 4;
static BYTE patch_sider_4[4] = "\x32\xc9\x90";  // xor cl,cl

/*
static BYTE pattern_dxgi[23] =
    "\x48\x33\xc4"
    "\x48\x89\x84\x24\xa0\x00\x00\x00"
    "\x4c\x8b\xf2"
    "\x48\x8b\xf1"
    "\x48\x8d\x54\x24\x30";

static int offs_dxgi = 0x1d;


00007FFF42B2263E | 48:33C4                  | xor rax,rsp                             |
00007FFF42B22641 | 48:898424 E0010000       | mov qword ptr ss:[rsp+1E0],rax          |
00007FFF42B22649 | 66:0F6F05 EF452200       | movdqa xmm0,xmmword ptr ds:[7FFF42D46C4 |
00007FFF42B22651 | 48:8BDA                  | mov rbx,rdx                             |
*/

static BYTE pattern_dxgi[23] =
    "\x48\x33\xc4"
    "\x48\x89\x84\x24\xa0\x00\x00\x00"
    "\x4c\x8b\xf2"
    "\x48\x8b\xf1"
    "\x48\x8d\x54\x24\x30";

static int offs_dxgi = 0x1d;

static BYTE pattern_ball_name[11] =
    "\x80\x79\x04\x00"
    "\x48\x8d\x51\x04"
    "\x75\x12";
static int offs_ball_name = 28;
static BYTE pattern_ball_name_head[3] = "\x50\x50";
static BYTE pattern_ball_name_tail[4] = "\x58\x58\x90";

static BYTE pattern_stadium_name[11] =
    "\x80\x79\x08\x00"
    "\x48\x8d\x51\x08"
    "\x75\x12";
static int offs_stadium_name = 28;
static BYTE pattern_stadium_name_head[3] = "\x50\x50";
static BYTE pattern_stadium_name_tail[4] = "\x58\x58\x90";

static BYTE pattern_set_stadium_choice[6] =
    "\xc6\x44\x24\x20\x01";
static int offs_set_stadium_choice = 11;

/*
0000000140497861 | E8 70B5EB00              | call <JMP.&XInputGetState>              |
0000000140497866 | 85C0                     | test eax,eax                            |
*/
static BYTE pattern_xinput[12] =
    "\xff\x50\x10"
    "\x8b\x4b\x0c"
    "\x48\x8d\x55\xb8"
    "\xe8";
static int offs_xinput = 11;

#endif
