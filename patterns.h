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


/*
00000001412AEF45 | 44 0F B6 80 16 03 00 00          | movzx r8d,byte ptr ds:[rax+316]         |
00000001412AEF4D | 41 3B E8                         | cmp ebp,r8d                             |
00000001412AEF50 | 75 2C                            | jne pes2018.1412AEF7E                   |
00000001412AEF52 | 80 78 50 00                      | cmp byte ptr ds:[rax+50],0              |
00000001412AEF56 | 48 8D 50 50                      | lea rdx,qword ptr ds:[rax+50]           | rdx:EntryPoint
00000001412AEF5A | 75 05                            | jne pes2018.1412AEF61                   |
00000001412AEF5C | 45 33 C0                         | xor r8d,r8d                             |
00000001412AEF5F | EB 0E                            | jmp pes2018.1412AEF6F                   |
00000001412AEF61 | 49 83 C8 FF                      | or r8,FFFFFFFFFFFFFFFF                  |
00000001412AEF65 | 49 FF C0                         | inc r8                                  |
00000001412AEF68 | 42 80 3C 02 00                   | cmp byte ptr ds:[rdx+r8],0              |
00000001412AEF6D | 75 F6                            | jne pes2018.1412AEF65                   |
00000001412AEF6F | 48 8B CE                         | mov rcx,rsi                             |
00000001412AEF72 | E8 E9 13 1F FF                   | call pes2018.1404A0360                  |
00000001412AEF77 | 48 83 7E 10 00                   | cmp qword ptr ds:[rsi+10],0             |
00000001412AEF7C | 75 3A                            | jne pes2018.1412AEFB8                   |
00000001412AEF7E | E8 FD 59 FB FF                   | call pes2018.141264980                  |
00000001412AEF83 | 0F B7 D5                         | movzx edx,bp                            |
00000001412AEF86 | 48 8B 48 40                      | mov rcx,qword ptr ds:[rax+40]           |
00000001412AEF8A | E8 F1 A5 FB FF                   | call pes2018.141269580                  |
00000001412AEF8F | 48 85 C0                         | test rax,rax                            | rax:EntryPoint
00000001412AEF92 | 74 12                            | je pes2018.1412AEFA6                    |

00000001412AEF94 | 4C 8B C6                         | mov r8,rsi                              |
00000001412AEF97 | BA 01 00 00 00                   | mov edx,1                               |
00000001412AEF9C | 48 8B C8                         | mov rcx,rax                             | rax:EntryPoint
00000001412AEF9F | E8 4C 13 FD FF                   | call pes2018.1412802F0                  |
00000001412AEFA4 | EB 12                            | jmp pes2018.1412AEFB8                   |
00000001412AEFA6 | 45 33 C0                         | xor r8d,r8d                             |
00000001412AEFA9 | 48 8D 15 A7 FD 14 01             | lea rdx,qword ptr ds:[1423FED57]        | rdx:EntryPoint
00000001412AEFB0 | 48 8B CE                         | mov rcx,rsi                             |

static BYTE pattern_def_stadium_name[9] = //[17] =
    "\x44\x0f\xb6\x80\xda\x03\x00\x00";
    //"\x44\x39\xc5"
    //"\x75\x3a"
    //"\x48\x89\xc1";
static int offs_def_stadium_name = 0x5b;
static BYTE pattern_def_stadium_name_head[3] = "\x75\x0c";
static BYTE pattern_def_stadium_name_tail[15] =
    "\x48\x8b\xd6"
    "\x48\x8b\xc8"
    "\xe8\x00\x00\x00\x00"
    "\xeb\x06"
    "\x90";
static int def_stadium_name_moved_call_offs_old = 0x08;
static int def_stadium_name_moved_call_offs_new = 0x14;

*/


static BYTE pattern_def_stadium_name[9] =
    "\x44\x0f\xb6\x80\x16\x03\x00\x00";
static int offs_def_stadium_name = 0x4d;
static BYTE pattern_def_stadium_name_head[3] = "\x75\x0c";
static BYTE pattern_def_stadium_name_tail[15] =
    "\x48\x8b\xd6"
    "\x48\x8b\xc8"
    "\xe8\x00\x00\x00\x00"
    "\xeb\x06"
    "\x90";
static int def_stadium_name_moved_call_offs_old = 0xd;
static int def_stadium_name_moved_call_offs_new = 0x17;

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
00000001418908FE | 48 8D 54 24 40              | lea rdx,qword ptr ss:[rsp+40]           |
0000000141890903 | 66 89 44 24 42              | mov word ptr ss:[rsp+42],ax             |
0000000141890908 | E8 CF 24 AC FF              | call <JMP.&XInputSetState>              |
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

#endif
