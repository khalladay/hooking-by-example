PUBLIC call_hook_payload
.code
call_hook_payload PROC
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 64 ; allocate space for xmm0-3 on the stack
	movups [rsp], xmm0
	movups [rsp + 16], xmm1
	movups [rsp + 32], xmm2
	movups [rsp + 48], xmm3
	sub rsp, 32 ; allocate shadow space for hook payload function
	nop ; 12 bytes of nops to replace with a call to hook payload
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	add rsp, 32
	movups xmm0, [rsp]
	movups xmm1, [rsp+16]
	movups xmm2, [rsp+32]
	movups xmm3, [rsp+48]
	add rsp, 64
	pop r9
	pop r8
	pop rdx
	pop rcx
	ret
call_hook_payload ENDP

END

; no instruction for pushing an xmm register onto stack.. wtf should I do with float args? 