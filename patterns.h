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
static BYTE pattern_set_settings_head[2] =
    "\x50";  // push rax
static BYTE pattern_set_settings_tail[2] =
    "\x58";

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
0000000141B1754D | 48:63C1                  | movsxd rax,ecx                          | rax:EntryPoint
0000000141B17550 | 8B44C4 04                | mov eax,dword ptr ss:[rsp+rax*8+4]      |
0000000141B17554 | 48:8B8D 50080000         | mov rcx,qword ptr ss:[rbp+850]          |
0000000141B1755B | 48:33CC                  | xor rcx,rsp                             |
...
0000000141B1755E | E8 DD9783FF              | call pes2018.141350D40                  |
0000000141B17563 | 4C:8D9C24 60090000       | lea r11,qword ptr ss:[rsp+960]          |
0000000141B1756B | 49:8B5B 30               | mov rbx,qword ptr ds:[r11+30]           |
*/

static BYTE pattern_trophy_table[18] =
    "\x48\x63\xc1"
    "\x8b\x44\xc4\x04"
    "\x48\x8b\x8d\x50\x08\x00\x00"
    "\x48\x33\xcc";
static int offs_trophy_table = 30;

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
0000000141C74670 | 4C:8D4C24 20                    | lea r9,qword ptr ss:[rsp+20]            |
0000000141C74675 | 4C:8D4424 30                    | lea r8,qword ptr ss:[rsp+30]            |
0000000141C7467A | 48:8BD6                         | mov rdx,rsi                             |
0000000141C7467D | 48:8BCF                         | mov rcx,rdi                             |
0000000141C74680 | FF50 50                         | call qword ptr ds:[rax+50]              |
*/
static BYTE pattern_create_swapchain[20] =
    "\x4c\x8d\x4c\x24\x20"
    "\x4c\x8d\x44\x24\x30"
    "\x48\x8b\xd6"
    "\x48\x8b\xcf"
    "\xff\x50\x50";
static int offs_create_swapchain = 0;

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

/*
00000001412AE875 | 44:0FB680 16030000              | movzx r8d,byte ptr ds:[rax+316]         |
00000001412AE87D | 41:3BE8                         | cmp ebp,r8d                             |
00000001412AE880 | 75 2C                           | jne pes2018.1412AE8AE                   |
00000001412AE882 | 8078 50 00                      | cmp byte ptr ds:[rax+50],0              |
00000001412AE886 | 48:8D50 50                      | lea rdx,qword ptr ds:[rax+50]           |
00000001412AE88A | 75 05                           | jne pes2018.1412AE891                   |
00000001412AE88C | 45:33C0                         | xor r8d,r8d                             |
00000001412AE88F | EB 0E                           | jmp pes2018.1412AE89F                   |
00000001412AE891 | 49:83C8 FF                      | or r8,FFFFFFFFFFFFFFFF                  |
00000001412AE895 | 49:FFC0                         | inc r8                                  |
00000001412AE898 | 42:803C02 00                    | cmp byte ptr ds:[rdx+r8],0              |
00000001412AE89D | 75 F6                           | jne pes2018.1412AE895                   |
00000001412AE89F | 48:8BCE                         | mov rcx,rsi                             |
00000001412AE8A2 | E8 E90F1FFF                     | call pes2018.14049F890                  |
00000001412AE8A7 | 48:837E 10 00                   | cmp qword ptr ds:[rsi+10],0             |
00000001412AE8AC | 75 3A                           | jne pes2018.1412AE8E8                   |
00000001412AE8AE | E8 0D57FBFF                     | call pes2018.141263FC0                  |
00000001412AE8B3 | 0FB7D5                          | movzx edx,bp                            |
00000001412AE8B6 | 48:8B48 40                      | mov rcx,qword ptr ds:[rax+40]           |
00000001412AE8BA | E8 01A3FBFF                     | call pes2018.141268BC0                  |

was:
00000001412AE8BF | 48:85C0                         | test rax,rax                            |
00000001412AE8C2 | 74 12                           | je pes2018.1412AE8D6                    |
00000001412AE8C4 | 4C:8BC6                         | mov r8,rsi                              |
00000001412AE8C7 | BA 01000000                     | mov edx,1                               |
00000001412AE8CC | 48:8BC8                         | mov rcx,rax                             |
00000001412AE8CF | E8 CC10FDFF                     | call pes2018.14127F9A0                  |
00000001412AE8D4 | EB 12                           | jmp pes2018.1412AE8E8                   |
00000001412AE8D6 | 45:33C0                         | xor r8d,r8d                             |
00000001412AE8D9 | 48:8D15 66041501                | lea rdx,qword ptr ds:[1423FED46]        |
00000001412AE8E0 | 48:8BCE                         | mov rcx,rsi                             |
00000001412AE8E3 | E8 A80F1FFF                     | call pes2018.14049F890                  |
00000001412AE8E8 | 48:8B5C24 30                    | mov rbx,qword ptr ss:[rsp+30]           |

becomes:
00000001412AE8BF | 48:85C0                         | test rax,rax                            |
00000001412AE8C2 | 75 0C                           | jne pes2018.1412AE8D0                   |
00000001412AE8C4 | 48:BA 4D9C0AA4FE7F0000          | mov rdx,sider.7FFEA40A9C4D              |
00000001412AE8CE | FFD2                            | call rdx                                |
00000001412AE8D0 | 4C:8BC6                         | mov r8,rsi                              |
00000001412AE8D3 | BA 01000000                     | mov edx,1                               |
00000001412AE8D8 | 48:8BC8                         | mov rcx,rax                             |
00000001412AE8DB | E8 C010FDFF                     | call pes2018.14127F9A0                  |
00000001412AE8E0 | EB 06                           | jmp pes2018.1412AE8E8                   |
00000001412AE8E2 | 90                              | nop                                     |
00000001412AE8E3 | E8 A80F1FFF                     | call pes2018.14049F890                  |
00000001412AE8E8 | 48:8B5C24 30                    | mov rbx,qword ptr ss:[rsp+30]           |
*/
static BYTE pattern_def_stadium_name[9] =
    "\x44\x0f\xb6\x80\x16\x03\x00\x00";
static int offs_def_stadium_name = 0x4d;
static BYTE pattern_def_stadium_name_head[3] = "\x75\x0c";
static BYTE pattern_def_stadium_name_tail[20] =
    "\x4c\x8b\xc6"
    "\xba\x01\x00\x00\x00"
    "\x48\x8b\xc8"
    "\xe8\x00\x00\x00\x00"
    "\xeb\x06"
    "\x90";
static int def_stadium_name_moved_call_offs_old = 0xd;
static int def_stadium_name_moved_call_offs_new = 0x19;

/*
00000001409D0C3D | 0FB693 00010000          | movzx edx,byte ptr ds:[rbx+100]         |
00000001409D0C44 | 48:8B48 48               | mov rcx,qword ptr ds:[rax+48]           |
00000001409D0C48 | 48:81C1 A8120300         | add rcx,312A8                           |
00000001409D0C4F | E8 1CEE8900              | call pes2018.14126FA70                  |
...
000000014126FA70 | 8851 2E                  | mov byte ptr ds:[rcx+2E],dl             |
000000014126FA73 | C3                       | ret                                     |
000000014126FA74 | CC                       | int3                                    |
000000014126FA75 | CC                       | int3                                    |
000000014126FA76 | CC                       | int3                                    |
000000014126FA77 | CC                       | int3                                    |
000000014126FA78 | CC                       | int3                                    |
000000014126FA79 | CC                       | int3                                    |
000000014126FA7A | CC                       | int3                                    |
000000014126FA7B | CC                       | int3                                    |
000000014126FA7C | CC                       | int3                                    |
000000014126FA7D | CC                       | int3                                    |
000000014126FA7E | CC                       | int3                                    |
000000014126FA7F | CC                       | int3                                    |
*/
static BYTE pattern_set_stadium_choice[20] =
    "\x0f\xb6\x93\x00\x01\x00\x00"
    "\x48\x8b\x48\x48"
    "\x48\x81\xc1\xa8\x12\x03\x00"
    "\xe8";
static int offs_set_stadium_choice = 18;

/*
0000000140496D97 | FF50 10                         | call qword ptr ds:[rax+10]              |
0000000140496D9A | 8B4B 0C                         | mov ecx,dword ptr ds:[rbx+C]            |
0000000140496D9D | 48:8D55 B8                      | lea rdx,qword ptr ss:[rbp-48]           |
0000000140496DA1 | E8 E0B2EB00                     | call <JMP.&XInputGetState>              |
...
0000000141352086 | FF25 F406BB0B                   | jmp qword ptr ds:[<&XInputGetState>]    |
000000014135208C | FF25 DE06BB0B                   | jmp qword ptr ds:[<&XInputSetState>]    |
*/
static BYTE pattern_xinput[12] =
    "\xff\x50\x10"
    "\x8b\x4b\x0c"
    "\x48\x8d\x55\xb8"
    "\xe8";
static int offs_xinput = 11;

/*
000000014000E6EB | C743 18 07000000         | mov dword ptr ds:[rbx+18],7             |
000000014000E6F2 | 8943 6C                  | mov dword ptr ds:[rbx+6C],eax           |
000000014000E6F5 | 837B 18 06               | cmp dword ptr ds:[rbx+18],6             |
000000014000E6F9 | 75 08                    | jne pes2018.14000E703                   |
*/
static BYTE pattern_data_ready[17] =
    "\xc7\x43\x18\x07\x00\x00\x00"
    "\x89\x43\x6c"
    "\x83\x7b\x18\x06"
    "\x75\x08";
static int offs_data_ready = 0xd1-0xa8;

/*
0000000140228E98 | 85C0                     | test eax,eax                            |
0000000140228E9A | 75 26                    | jne pes2018.140228EC2                   |
0000000140228E9C | 8BD3                     | mov edx,ebx                             |
0000000140228E9E | 48:8BCF                  | mov rcx,rdi                             |
0000000140228EA1 | E8 C29BFDFF              | call pes2018.140202A68                  |
*/
static BYTE pattern_call_to_move[10] =
    "\x85\xc0"
    "\x75\x26"
    "\x8b\xd3"
    "\x48\x8b\xcf";
static int offs_call_to_move = 0x68-0x50;

/*
0000000141F0DA7D | 25 00C0FFFF                   | and eax,FFFFC000                           |
0000000141F0DA82 | 3D 0040FEFF                   | cmp eax,FFFE4000                           |
0000000141F0DA87 | 75 09                         | jne pes2021.141F0DA92                      |
0000000141F0DA89 | C741 20 00000D00              | mov dword ptr ds:[rcx+20],D0000            |
0000000141F0DA90 | EB 11                         | jmp pes2021.141F0DAA3                      |
0000000141F0DA92 | 48:8D41 20                    | lea rax,qword ptr ds:[rcx+20]              |
0000000141F0DA96 | 4C:8D5424 18                  | lea r10,qword ptr ss:[rsp+18]              |
0000000141F0DA9B | 49:3BC2                       | cmp rax,r10                                |
0000000141F0DA9E | 74 03                         | je pes2021.141F0DAA3                       |
0000000141F0DAA0 | 44:8900                       | mov dword ptr ds:[rax],r8d                 | set edit team id
0000000141F0DAA3 | 8B4424 28                     | mov eax,dword ptr ss:[rsp+28]              |
0000000141F0DAA7 | 8941 28                       | mov dword ptr ds:[rcx+28],eax              |
0000000141F0DAAA | 8B4424 30                     | mov eax,dword ptr ss:[rsp+30]              |
0000000141F0DAAE | 8941 2C                       | mov dword ptr ds:[rcx+2C],eax              |
0000000141F0DAB1 | B0 01                         | mov al,1                                   |
0000000141F0DAB3 | 44:8949 24                    | mov dword ptr ds:[rcx+24],r9d              |
0000000141F0DAB7 | 48:8951 10                    | mov qword ptr ds:[rcx+10],rdx              |
0000000141F0DABB | 48:C701 02000000              | mov qword ptr ds:[rcx],2                   |
0000000141F0DAC2 | C3                            | ret                                        |
*/
static BYTE pattern_set_edit_team_id[20] =
    "\x25\x00\xc0\xff\xff"
    "\x3d\x00\x40\xfe\xff"
    "\x75\x09"
    "\xc7\x41\x20\x00\x00\x0d\x00";
static int offs_set_edit_team_id = 54;


/*
0000000140B9F307 | 49 89 06                  | mov qword ptr ds:[r14],rax           | rax:EntryPoint
0000000140B9F30A | 41 C6 47 FE 01            | mov byte ptr ds:[r15-2],1            |
0000000140B9F30F | 41 C6 07 00               | mov byte ptr ds:[r15],0              |
0000000140B9F313 | 8B D3                     | mov edx,ebx                          |
0000000140B9F315 | 48 8B CF                  | mov rcx,rdi                          |
*/
static BYTE pattern_check_kit_choice[13] =
    "\x49\x89\x06"
    "\x41\xc6\x47\xfe\x01"
    "\x41\xc6\x07\x00";
static int offs_check_kit_choice = 3;

/*
Find the code location where the "base addr" is read, and remember this addr.
Look for this code sequence:

0000000141D0B86D | 4D 85 FF                        | test r15,r15                       |
0000000141D0B870 | 75 23                           | jne pes2019.141D0B895              |
0000000141D0B872 | 48 83 7D 60 10                  | cmp qword ptr ss:[rbp+60],10       |
0000000141D0B877 | 72 17                           | jb pes2019.141D0B890               |
0000000141D0B879 | C7 44 24 60 02 00 00 00         | mov dword ptr ss:[rsp+60],2        |
*/
static BYTE pattern_get_uniparam[21] =
    "\x4d\x85\xff"
    "\x75\x23"
    "\x48\x83\x7d\x60\x10"
    "\x72\x17"
    "\xc7\x44\x24\x60\x02\x00\x00\x00";
static int offs_get_uniparam = -4;

/*
00000001505F09CC | 44 0F B6 4B 4E                     | movzx r9d,byte ptr ds:[rbx+4E]       |
00000001505F09D1 | 44 0F B6 43 4D                     | movzx r8d,byte ptr ds:[rbx+4D]       |
00000001505F09D6 | 0F B6 53 4C                        | movzx edx,byte ptr ds:[rbx+4C]       |
*/
static BYTE pattern_kit_status[15] =
    "\x44\x0f\xb6\x4b\x4e"
    "\x44\x0f\xb6\x43\x4d"
    "\x0f\xb6\x53\x4c";
static int offs_kit_status = 0;

/*
0000000141BC3EFF | 33 D0                        | xor edx,eax                          |
0000000141BC3F01 | 81 E2 FF 3F 00 00            | and edx,3FFF                         |
0000000141BC3F07 | 33 D0                        | xor edx,eax                          |
0000000141BC3F09 | 41 89 51 10                  | mov dword ptr ds:[r9+10],edx         |  set team id (edit mode?)
*/
static BYTE pattern_set_team_for_kits[15] =
    "\x33\xd0"
    "\x81\xe2\xff\x3f\x00\x00"
    "\x33\xd0"
    "\x41\x89\x51\x10";
static int offs_set_team_for_kits = 0;

/*
0000000141BC4F1D | 89 4A FC                     | mov dword ptr ds:[rdx-4],ecx         |  clear (reset) team id (for kits)
0000000141BC4F20 | C7 42 18 FF FF 00 00         | mov dword ptr ds:[rdx+18],FFFF       |
0000000141BC4F27 | C7 42 30 FF FF FF FF         | mov dword ptr ds:[rdx+30],FFFFFFFF   |
*/
static BYTE pattern_clear_team_for_kits[18] =
    "\x89\x4a\xfc"
    "\xc7\x42\x18\xff\xff\x00\x00"
    "\xc7\x42\x30\xff\xff\xff\xff";
static int offs_clear_team_for_kits = 0;

static BYTE pattern_uniparam_loaded[19] =
    "\x48\x89\x46\x40"
    "\xc6\x46\x62\x01"
    "\x48\x8b\x5c\x24\x48"
    "\x48\x8b\x74\x24\x50";
static int offs_uniparam_loaded = -(0x81e - 0x7ee - 8);

#endif
