//based on https://golang.org/src/runtime/sys_windows_amd64.s
#define maxargs 18
//func hgSyscall(callid uintptr,syscallA uintptr,argh ...uintptr) (uint32, error)
TEXT ·hgSyscall(SB),$0-56
    PUSHQ CX
	BYTE $0x90			//NOP
	XORQ AX,AX
	BYTE $0x90			//NOP
	MOVW callid+0(FP), AX

	BYTE $0x90			//NOP

    XORQ R15,R15
    MOVQ syscallA+8(FP), R15

	BYTE $0x90			//NOP
	//put variadic size into CX
	MOVQ argh_len+24(FP),CX
	BYTE $0x90			//NOP
	//put variadic pointer into SI
	MOVQ argh_base+16(FP),SI
	BYTE $0x90			//NOP


	// SetLastError(0).
	MOVQ	0x30(GS), DI
	BYTE $0x90			//NOP
	MOVL	$0, 0x68(DI)
	BYTE $0x90			//NOP


	SUBQ	$(maxargs*8), SP	// room for args
	BYTE $0x90			//NOP

	// Fast version, do not store args on the stack.
	CMPL	CX, $4
	BYTE $0x90			//NOP
	JLE	loadregs

	// Check we have enough room for args.
	CMPL	CX, $maxargs
	BYTE $0x90			//NOP
	JLE	2(PC)
	INT	$3			// not enough room -> crash
	BYTE $0x90			//NOP


	// Copy args to the stack.
	MOVQ	SP, DI
	BYTE $0x90			//NOP
	CLD
	BYTE $0x90			//NOP
	REP; MOVSQ
	BYTE $0x90			//NOP
	MOVQ	SP, SI
	BYTE $0x90			//NOP
loadregs:
    //move the stack pointer????? why????
	//SUBQ	$8, SP

	// Load first 4 args into correspondent registers.
	MOVQ	0(SI), CX
	MOVQ	8(SI), DX
	MOVQ	16(SI), R8
	MOVQ	24(SI), R9
	// Floating point arguments are passed in the XMM
	// registers. Set them here in case any of the arguments
	// are floating point values. For details see
	//	https://msdn.microsoft.com/en-us/library/zthk2dkh.aspx
	MOVQ	CX, X0
	MOVQ	DX, X1
	MOVQ	R8, X2
	MOVQ	R9, X3

    //mov r10, rax
	MOVQ CX, R10

    //syscall;ret
    CALL R15

    ADDQ	$((maxargs)*8), SP

    // Return result.
    POPQ	CX
    MOVL	AX, errcode+40(FP)

    RET




//func getModuleLoadedOrder(i int) (start uintptr, size uintptr)
TEXT ·getMLO(SB), $0-32
	//All operations push values into AX
	//PEB
	MOVQ 0x60(GS), AX
	BYTE $0x90			//NOP
	//PEB->LDR
	MOVQ 0x18(AX),AX
	BYTE $0x90			//NOP

	//LDR->InMemoryOrderModuleList
	MOVQ 0x20(AX),AX
	BYTE $0x90			//NOP

	//loop things
	XORQ R10,R10
startloop:
	CMPQ R10,i+0(FP)
	BYTE $0x90			//NOP
	JE endloop
	BYTE $0x90			//NOP
	//Flink (get next element)
	MOVQ (AX),AX
	BYTE $0x90			//NOP
	INCQ R10
	JMP startloop
endloop:
	//Flink - 0x10 -> _LDR_DATA_TABLE_ENTRY
	//_LDR_DATA_TABLE_ENTRY->DllBase (offset 0x30)

	MOVQ 0x30(AX),CX
	BYTE $0x90			//NOP
	MOVQ CX, size+16(FP)
	BYTE $0x90			//NOP


	MOVQ 0x20(AX),CX
	BYTE $0x90			//NOP
    MOVQ CX, start+8(FP)
    BYTE $0x90			//NOP


	MOVQ AX,CX
	BYTE $0x90			//NOP
	ADDQ $0x38,CX
	BYTE $0x90			//NOP
	MOVQ CX, modulepath+24(FP)
	//SYSCALL
	RET

