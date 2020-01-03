lea eax, [0x600000]
lea ebx, [edi*2+edi]  
lea ecx, [edi*4+edi]
lea edx, [edi*8+edi]
done:

mov eax, [0x600004]
mov ebx, [0x600008]
neg ebx
lea edx, [eax + ebx]
mov eax, [0x600000]
neg eax
lea ecx, [edx + eax]
mov [0x60000c], ecx
done:

mov al, [0x600000]
xor al, 0x20
mov [0x600001], al
done:

and eax, 0xFFFDFFFF
done:


shr ax, 5
mov [0x600000], al
done:

cmp eax, 0
JGE L11
mov edi, -1
mov [0x600000], edi
jmp L12
L11:
mov edi, 1
mov [0x600000], edi
L12:
cmp ebx, 0
JGE L21
mov edi, -1
mov [0x600004], edi
jmp L22
L21:
mov edi, 1
mov [0x600004], edi
L22:
cmp ecx, 0
JGE L31
mov edi, -1
mov [0x600008], edi
jmp L32
L31:
mov edi, 1
mov [0x600008], edi
L32:
cmp edx, 0
JGE L41
mov edi, -1
mov [0x60000C], edi
jmp L42
L41:
mov edi, 1
mov [0x60000C], edi
L42:
done:



lea edx,[0x600000]
mov ecx,0
L1:
mov al, [edx + ecx]
cmp al, 0x60
jg L2
xor al, 0x20
L2:
mov [edx+ecx+0x10], al
inc ecx
cmp ecx,15
jl L1
done:

lea edx, [0x600000]
mov ecx,0
L1:
shl ax,1
setc bl
add bl, 48
mov [edx + ecx], bl
inc ecx
cmp ecx, 16
jl L1
done:

lea edx, [0x600000]
mov ecx,0
L3:
mov edi, 0
L2:
mov eax, [edx + edi]
mov ebx, [edx + edi + 4]
cmp eax,ebx
jle L1
mov [edx + edi + 4], eax
mov [edx + edi], ebx
L1:
mov eax, ecx
neg eax
add eax, 36
add edi, 4
cmp edi, eax
jl L2
add ecx, 4
cmp ecx, 36
jl L3
done:

mov eax, [0x600000]
mov ebx, [0x600004]
add eax, ebx
mov ebx, [0x600008]
imul eax, ebx
mov [0x60000c], eax
done:

mov eax, [0x600000]
neg eax
mov ebx, [0x600004]
imul eax, ebx
mov ebx, [0x600008]
add eax, ebx
done:

mov eax, [0x600000]
imul eax, 5
mov ebx, [0x600004]
sub ebx, 3
idiv eax, ebx
mov [0x600008], eax
done:

mov eax, [0x600000]
mov ebx, 5
neg ebx
imul eax, ebx
mov edi, eax
mov eax, [0x600004]
neg eax
mov edx, 0
mov ebx, [0x600008]
div ebx
mov esi, edx
mov eax, edi
mov edx, 0
mov ebx, esi
div ebx
mov [0x60000c], eax
done:


mov eax, [0x600008]
neg ebx
add eax, ebx
mov edi, eax
mov eax, [0x600000]
mov ebx, [0x600004]
neg ebx
imul eax, ebx
cdq
idiv edi
mov [0x600008], eax
done:


call mysub
jmp    exit
mysub:
    pop rax
    push rax
    ret
exit:
done:



mov rdi, 30
call REC
jmp exit
REC:
    push rbp
    mov rbp, rsp
    mov rbx, rdi
    cmp rbx, 0
    jg L1
    mov rax, 0
    jmp RETRN
L1:
    cmp rbx, 1
    jne L2
    mov rax, 1
    jmp RETRN
L2:
    push rbx
    mov rdi, rbx
    sub rdi, 1
    call REC
    pop rbx
    imul rax, 2
    push rax
    mov rdi, rbx
    sub rdi, 2
    call REC
    pop rbx
    imul rax, 3
    add rax, rbx
RETRN:
    leave
    ret
exit:
done:

