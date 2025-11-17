; ScoopyNG x64 Assembly Functions
; Author: Tobias Klein, 2008 [ www.trapkit.de ]
; Modified by: Real Ursus, 2016-2025 (North Pole)
; Refactored for x64 support

.CODE

;-----------------------------------------------------------------------------
; GetIdtBase - Get Interrupt Descriptor Table base address
; Returns: RAX = IDT base address (64-bit)
;-----------------------------------------------------------------------------
GetIdtBase PROC
    LOCAL idtr[10]:BYTE

    sidt idtr                ; Store IDT register to local variable
    mov rax, QWORD PTR idtr[2] ; Get base address (bytes 2-9 for x64)
    ret
GetIdtBase ENDP

;-----------------------------------------------------------------------------
; GetLdtBase - Get Local Descriptor Table base address
; Returns: RAX = LDT base selector
;-----------------------------------------------------------------------------
GetLdtBase PROC
    LOCAL ldtr[8]:BYTE

    ; Initialize to 0xDEADBEEF pattern for detection
    mov QWORD PTR ldtr, 0DEADBEEFh

    sldt WORD PTR ldtr       ; Store LDT register
    movzx rax, WORD PTR ldtr ; Zero-extend to 64-bit
    ret
GetLdtBase ENDP

;-----------------------------------------------------------------------------
; GetGdtBase - Get Global Descriptor Table base address
; Returns: RAX = GDT base address (64-bit)
;-----------------------------------------------------------------------------
GetGdtBase PROC
    LOCAL gdtr[10]:BYTE

    sgdt gdtr                ; Store GDT register to local variable
    mov rax, QWORD PTR gdtr[2] ; Get base address (bytes 2-9 for x64)
    ret
GetGdtBase ENDP

;-----------------------------------------------------------------------------
; GetTaskRegister - Get Task Register (STR)
; Returns: RAX = Task register value
;-----------------------------------------------------------------------------
GetTaskRegister PROC
    LOCAL tr[8]:BYTE

    mov QWORD PTR tr, 0
    str WORD PTR tr          ; Store task register
    movzx rax, WORD PTR tr   ; Zero-extend to 64-bit
    ret
GetTaskRegister ENDP

;-----------------------------------------------------------------------------
; VMwareGetVersion - Query VMware version via I/O port
; Parameters: None
; Returns: RAX = magic value (0x564D5868 if VMware detected)
;          RDX = version type (1=Express, 2=ESX, 3=GSX, 4=Workstation)
;-----------------------------------------------------------------------------
VMwareGetVersion PROC
    push rbx
    push rcx

    ; Setup VMware backdoor call
    mov eax, 564D5868h       ; VMware magic value 'VMXh'
    xor ebx, ebx             ; Clear EBX (must not equal magic)
    mov ecx, 0Ah             ; Command 0x0A: Get VMware version
    mov edx, 5658h           ; VMware I/O port 'VX'

    ; Perform the backdoor call
    ; This will cause an exception on non-VMware systems
    in eax, dx               ; Read from VMware backdoor port

    ; Save results
    mov rax, rbx             ; Return magic value in RAX
    mov rdx, rcx             ; Return version in RDX

    pop rcx
    pop rbx
    ret
VMwareGetVersion ENDP

;-----------------------------------------------------------------------------
; VMwareGetMemorySize - Query VMware memory size via I/O port
; Parameters: None
; Returns: RAX = memory size (> 0 if VMware detected)
;-----------------------------------------------------------------------------
VMwareGetMemorySize PROC
    push rbx
    push rcx
    push rdx

    ; Setup VMware backdoor call
    mov eax, 564D5868h       ; VMware magic value 'VMXh'
    mov ecx, 14h             ; Command 0x14: Get memory size
    mov edx, 5658h           ; VMware I/O port 'VX'

    ; Perform the backdoor call
    in eax, dx               ; Read from VMware backdoor port

    ; Result already in RAX

    pop rdx
    pop rcx
    pop rbx
    ret
VMwareGetMemorySize ENDP

;-----------------------------------------------------------------------------
; SwitchToCodeSegment - Helper function for test7 emulation detection
; Switches to a custom code segment descriptor
;-----------------------------------------------------------------------------
SwitchToCodeSegment PROC
    pop rax                  ; Get return address
    push 0Fh                 ; Push custom CS selector
    push rax                 ; Push return address
    retfq                    ; Far return to new CS:RIP
SwitchToCodeSegment ENDP

END
