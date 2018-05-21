;------------------------------------------
;Descr  : hooking utils
;
;Small functions to help with hooking
;Typically, they would call a function
;from sider, which does all the actual work 
;------------------------------------------

extern sider_read_file:proc
extern sider_alloc_mem:proc

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

sider_alloc_mem_hk proc

        sub     rsp,28h
        call    sider_alloc_mem
        add     rsp,28h
        mov     qword ptr [rdi+rbx*8+18h],rax  ;run overwritten code
        movsxd  rcx,dword ptr [rdi+254h]       ;run overwritten code
        ret

sider_alloc_mem_hk endp

end
