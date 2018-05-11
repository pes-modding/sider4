;------------------------------------------
;Descr  : hooking utils
;
;Small functions to help with hooking
;Typically, they would call a function
;from sider, which does all the actual work 
;------------------------------------------

extern sider_read_file:proc

.code
sider_read_file_hk proc

        push    r12
        push    0
        sub     rsp,20h
        call    sider_read_file
        add     rsp,30h
        ret

sider_read_file_hk endp
end
