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

        mov     rcx,rsi
        mov     rdx,rbx
        sub     rsp,28h
        call    sider_get_size
        add     rsp,28h
        mov     rcx,qword ptr [rdi+1d8h]
        mov     eax,1
        ret

sider_get_size_hk endp

sider_extend_cpk_hk proc

        mov     rax,1000000000000000h
        mov     qword ptr [rdi+8],rax
        mov     qword ptr [r13],rdi
        ret

sider_extend_cpk_hk endp

sider_mem_copy_hk proc

        add     r8,r10
        push    r12
        sub     rsp,20h
        call    sider_mem_copy
        add     rsp,28h
        mov     qword ptr [rdi+10h],rbx
        ret

sider_mem_copy_hk endp

sider_lookup_file_hk proc

        sub     rsp,38h
        mov     [rsp+30h],rax
        call    sider_lookup_file
        mov     rax,[rsp+30h]
        add     rsp,38h
        lea     rcx,qword ptr [rdi+110h]
        mov     r8,rsi
        lea     rdx,qword ptr [rsp+28h]
        ret

sider_lookup_file_hk endp

end
