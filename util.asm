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
extern sider_trophy_check:proc
extern sider_context_reset:proc

.code
sider_read_file_hk proc

        mov     rax,[rsp+28h]
        sub     rsp,38h
        mov     [rsp+20h],rax
        mov     [rsp+28h],r12
        call    sider_read_file
        mov     r12,[rsp+28h]
        add     rsp,38h
        ret

sider_read_file_hk endp

sider_get_size_hk proc

        sub     rsp,28h
        mov     [rsp+20h],rdx
        mov     rcx,rsi
        mov     rdx,rbx
        call    sider_get_size
        mov     rcx,qword ptr [rdi+1d8h]
        mov     eax,1
        mov     rdx,[rsp+20h]
        add     rsp,28h
        ret

sider_get_size_hk endp

sider_extend_cpk_hk proc

        mov     rax,1000000000000000h
        mov     qword ptr [rdi+8],rax
        mov     qword ptr [r13],rdi
        ret

sider_extend_cpk_hk endp

sider_mem_copy_hk proc

        push    r12
        sub     rsp,20h
        add     r8,r10
        call    sider_mem_copy
        mov     qword ptr [rdi+10h],rbx
        add     rsp,20h
        pop     r12
        ret

sider_mem_copy_hk endp

sider_lookup_file_hk proc

        push    rax
        sub     rsp,20h
        call    sider_lookup_file
        lea     rcx,qword ptr [rdi+110h]
        mov     r8,rsi
        lea     rdx,qword ptr [rsp+50h]
        add     rsp,20h
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

        push    rdx
        push    r9
        push    r10
        push    r11
        sub     rsp,40h
        movsxd  rax,dword ptr [r8]
        mov     [rsp+30h],rax
        cmp     eax,2
        jge     done
        imul    r8,rax,520h
        add     rcx,104h
        add     rcx,r8
        mov     [rsp+20h],rcx
        mov     [rsp+28h],r8
        call    sider_set_team_id
        mov     rcx,[rsp+20h]
        mov     r8,[rsp+28h]
        mov     rax,[rsp+30h]
done:   add     rsp,40h
        pop     r11
        pop     r10
        pop     r9
        pop     rdx
        ret

sider_set_team_id_hk endp

;00000001412A4FD5 | 0F B6 82 8B 00 00 00               | movzx eax,byte ptr ds:[rdx+8B]          |
;00000001412A4FDC | 88 81 8B 00 00 00                  | mov byte ptr ds:[rcx+8B],al             |
;00000001412A4FE2 | 48 8B C1                           | mov rax,rcx                             |
;00000001412A4FE5 | C3                                 | ret                                     |

sider_set_settings_hk proc

        pushfq
        push    rcx
        push    rdx
        push    r8
        push    r9
        push    r10
        push    r11
        sub     rsp,200h
        movzx eax,byte ptr [rdx+8Bh]
        mov byte ptr [rcx+8Bh],al
        call    sider_set_settings
        add     rsp,200h
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx
        popfq
        ret

sider_set_settings_hk endp

sider_trophy_check_hk proc

        push    rdx
        sub     rsp,20h
        mov     [rsp+50h],rdi
        call    sider_trophy_check
        mov     rcx,rax
        mov     rdx,[rsp+20h]
        mov     rbx,rdx
        movzx   edi,cx
        mov     eax,0ffffh
        add     rsp,20h
        pop     rdx
        ret

sider_trophy_check_hk endp

sider_context_reset_hk proc

        sub     rsp,28h
        mov     qword ptr [rbx+84h],rcx
        mov     qword ptr [rbx+159ach],0ffffffffh
        call    sider_context_reset
        add     rsp,28h
        ret

sider_context_reset_hk endp

end
