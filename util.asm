;------------------------------------------
;Descr  : hooking utils
;
;Small functions to help with hooking
;Typically, they would call a function
;from sider, which does all the actual work 
;------------------------------------------

extern sider_read_file:proc
extern sider_get_size:proc
extern sider_mem_copy:proc
extern sider_lookup_file:proc
extern sider_set_team_id:proc
extern sider_set_settings:proc

.code
sider_read_file_hk proc

        mov     rax,[rsp+28h]
        sub     rsp,8
        push    r12
        push    rax
        sub     rsp,20h
        call    sider_read_file
        add     rsp,38h
        ret

sider_read_file_hk endp

sider_get_size_hk proc

        sub     rsp,8
        mov     rcx,rsi
        mov     rdx,rbx
        sub     rsp,20h
        call    sider_get_size
        add     rsp,20h
        mov     rcx,qword ptr [rdi+1d8h]
        mov     eax,1
        add     rsp,8
        ret

sider_get_size_hk endp

sider_extend_cpk_hk proc

        mov     rax,1000000000000000h
        mov     qword ptr [rdi+8],rax
        mov     qword ptr [r13],rdi
        ret

sider_extend_cpk_hk endp

sider_mem_copy_hk proc

        sub     rsp,10h
        add     r8,r10
        push    r12
        sub     rsp,20h
        call    sider_mem_copy
        add     rsp,28h
        mov     qword ptr [rdi+10h],rbx
        add     rsp,10h
        ret

sider_mem_copy_hk endp

sider_lookup_file_hk proc

        push    rax
        sub     rsp,30h
        call    sider_lookup_file
        add     rsp,20h
        lea     rcx,qword ptr [rdi+110h]
        mov     r8,rsi
        lea     rdx,qword ptr [rsp+40h]
        add     rsp,10h
        pop     rax
        ret

sider_lookup_file_hk endp

;000000014126DF00 | 49 63 00                           | movsxd rax,dword ptr ds:[r8]            | prep to write team info
;000000014126DF03 | 83 F8 02                           | cmp eax,2                               |
;000000014126DF06 | 7D 16                              | jge pes2018.14126DF1E                   |
;000000014126DF08 | 4C 69 C0 20 05 00 00               | imul r8,rax,520                         |
;000000014126DF0F | 48 81 C1 04 01 00 00               | add rcx,104                             |
;000000014126DF16 | 49 03 C8                           | add rcx,r8                              |
;000000014126DF19 | E9 D2 72 7D FF                     | jmp pes2018.140A451F0                   |
;000000014126DF1E | C3                                 | ret                                     |

sider_set_team_id_hk proc

        movsxd  rax,dword ptr [r8]
        cmp     eax,2
        jge     done
        imul    r8,rax,520h
        add     rcx,104h
        add     rcx,r8
        push    rax
        push    rcx
        push    rdx
        push    r8
        push    r9
        push    r10
        push    r11
        sub     rsp,20h
        call    sider_set_team_id
        add     rsp,20h
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx
        pop     rax
done:   ret

sider_set_team_id_hk endp

;00000001412A4FD5 | 0F B6 82 8B 00 00 00               | movzx eax,byte ptr ds:[rdx+8B]          |
;00000001412A4FDC | 88 81 8B 00 00 00                  | mov byte ptr ds:[rcx+8B],al             |
;00000001412A4FE2 | 48 8B C1                           | mov rax,rcx                             |
;00000001412A4FE5 | C3                                 | ret                                     |

sider_set_settings_hk proc

        push    rcx
        push    rdx
        movzx   eax,byte ptr [rdx+8bh]
        mov     byte ptr [rcx+8bh],al
        sub     rsp,28h
        call    sider_set_settings
        add     rsp,28h
        pop     rdx
        pop     rcx
        ret

sider_set_settings_hk endp

end
