INCLUDE Irvine32.inc
INCLUDELIB kernel32.lib

FindFirstFileA PROTO :PTR BYTE, :PTR BYTE
FindNextFileA PROTO :DWORD, :PTR BYTE
FindClose PROTO :DWORD
CreateFileA PROTO :PTR BYTE, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle PROTO :DWORD
GetFileSize PROTO :DWORD, :DWORD
FindFirstChangeNotificationA PROTO :PTR BYTE, :DWORD, :DWORD
FindNextChangeNotification PROTO :DWORD
FindCloseChangeNotification PROTO :DWORD
WaitForSingleObject PROTO :DWORD, :DWORD
Sleep PROTO :DWORD

ScanDir PROTO, dirPtr:PTR BYTE
ProcessFile PROTO, pathPtr:PTR BYTE
HashFileSHA PROTO, pathPtr:PTR BYTE
FindEntry PROTO, pathPtr:PTR BYTE
PrintStatus PROTO, pathPtr:PTR BYTE, stCode:DWORD
ReportEvent PROTO, pathPtr:PTR BYTE, stCode:DWORD
LogEvent PROTO, evPtr:PTR BYTE, pathPtr:PTR BYTE
SaveFile PROTO, namePtr:PTR BYTE, bufPtr:PTR BYTE, dataLen:DWORD, accMode:DWORD, dispMode:DWORD
ReadWholeFile PROTO, namePtr:PTR BYTE, bufPtr:PTR BYTE, maxLen:DWORD
HmacSha256 PROTO, msgPtr:PTR BYTE, msgLen:DWORD, outPtr:PTR BYTE
PrintPadded PROTO, pathPtr:PTR BYTE

ACC_READ EQU 80000000h
ACC_WRITE EQU 40000000h
ACC_APPEND EQU 00000004h
SHARE_RW EQU 3
SHARE_R EQU 1
MODE_CREATE EQU 2
MODE_OPEN EQU 3
MODE_ALWAYS EQU 4
ATTR_NORMAL EQU 80h
ATTR_DIR EQU 10h
ATTR_REPARSE EQU 400h
BAD_HANDLE EQU -1
NOTIFY_FILTER EQU 1Bh

F_ATTR EQU 0
F_NAME EQU 44

C_GREEN EQU 10
C_RED EQU 12
C_YELLOW EQU 14
C_WHITE EQU 15
C_CYAN EQU 11

MAX_FILES EQU 64
MAX_DEPTH EQU 8
BUF_SIZE EQU 4096
BASE_TEXT_MAX EQU 32768
HIST_MAX EQU 3200

E_PATH EQU 0
E_HASH EQU 260
E_SEEN EQU 292
E_STATE EQU 296
E_ORIGIN EQU 300
ENTRY_SIZE EQU 304

ST_PASS EQU 0
ST_TAMPER EQU 1
ST_MISSING EQU 2
ST_NEW EQU 3
ST_LOCKED EQU 4
ST_RESTORED EQU 5

.data
rootDir BYTE "monitored",0
baselineName BYTE "baseline.txt",0
sigName BYTE "baseline.sig",0
logName BYTE "fim_history.log",0
starStr BYTE "\*",0
sepStr BYTE " | ",0
hmacKey BYTE "FIM-Secret-Key-COAL-2026!",0
hexTable BYTE "0123456789ABCDEF"

evTamper BYTE "TAMPERED",0
evMissing BYTE "MISSING ",0
evNew BYTE "NEWFILE ",0
evLocked BYTE "LOCKED  ",0
evRestored BYTE "RESTORED",0
evBaseline BYTE "BASELINE",0
evAlert BYTE "ALERT   ",0
evWatch BYTE "WATCH   ",0
evVerified BYTE "VERIFIED",0

msgPass BYTE "[PASS]  - Hash matches",0
msgTamper BYTE "[TAMPERED]  - Hash mismatch detected!",0
msgMissing BYTE "[MISSING]  - File not found!",0
msgNew BYTE "[NEW]  - File is not in the baseline!",0
msgLocked BYTE "[LOCKED]  - File cannot be opened!",0
msgRestored BYTE "[RESTORED]  - Hash matches baseline again",0

stMsg DWORD OFFSET msgPass, OFFSET msgTamper, OFFSET msgMissing
    DWORD OFFSET msgNew, OFFSET msgLocked, OFFSET msgRestored
stColor DWORD C_GREEN, C_RED, C_YELLOW, C_YELLOW, C_YELLOW, C_GREEN
stEvt DWORD 0, OFFSET evTamper, OFFSET evMissing
    DWORD OFFSET evNew, OFFSET evLocked, OFFSET evRestored

msgTitle BYTE "==============================================",0Dh,0Ah
    BYTE "   ASSEMBLY FILE INTEGRITY MONITOR  (FIM PRO)",0Dh,0Ah
    BYTE "   SHA-256 | HMAC seal | Recursive | Real-time",0Dh,0Ah
    BYTE "==============================================",0
msgOpt1 BYTE "  [1] Initialize Baseline (recursive scan)",0
msgOpt2 BYTE "  [2] Run Integrity Check",0
msgOpt3 BYTE "  [3] Real-Time Monitor",0
msgOpt4 BYTE "  [4] View Event History",0
msgOpt5 BYTE "  [5] Exit",0
msgPrompt BYTE "  Select an option: ",0
msgBye BYTE "Goodbye - stay secure!",0

msgInitHdr BYTE "--- Creating baseline from folder 'monitored' ---",0
msgCheckHdr BYTE "--- Integrity check ---",0
msgMonHdr BYTE "--- Real-time monitor ---",0
msgHistHdr BYTE "--- Event history (most recent entries) ---",0
msgHashed BYTE "[HASHED]  SHA-256 ",0
msgDots BYTE "...",0
msgOverwrite BYTE "A baseline already exists. Overwrite it? (Y/N): ",0
msgCancelled BYTE "Cancelled. Existing baseline kept.",0
msgEmpty BYTE "No readable files found in 'monitored'. Create the folder and add files.",0
msgFull BYTE "[LIMIT]  Too many files, extra files ignored.",0
msgSealed BYTE "Baseline saved and sealed (baseline.txt + baseline.sig).",0
msgSaveErr BYTE "ERROR: could not write baseline files.",0
msgNoBase BYTE "ERROR: baseline not found. Run option [1] first.",0
msgBroken BYTE "[ALERT]  BASELINE TAMPERED! Seal does not match - check refused.",0
msgSumPass BYTE "Summary -> Passed: ",0
msgSumTam BYTE "  Tampered: ",0
msgSumMis BYTE "  Missing: ",0
msgSumNew BYTE "  New: ",0
msgAllOk BYTE "All monitored files are intact.",0
msgWatching BYTE "Baseline verified. Watching 'monitored' (all sub-folders). Press any key to stop...",0
msgStopped BYTE "Monitoring stopped.",0
msgNoNotify BYTE "ERROR: could not start change notification (does 'monitored' exist?).",0
msgNoHist BYTE "No events have been logged yet.",0
msgWas BYTE "      baseline: ",0
msgNow BYTE "..  now: ",0
msgDots2 BYTE "..",0

K256 DWORD 0428A2F98h, 071374491h, 0B5C0FBCFh, 0E9B5DBA5h
    DWORD 03956C25Bh, 059F111F1h, 0923F82A4h, 0AB1C5ED5h
    DWORD 0D807AA98h, 012835B01h, 0243185BEh, 0550C7DC3h
    DWORD 072BE5D74h, 080DEB1FEh, 09BDC06A7h, 0C19BF174h
    DWORD 0E49B69C1h, 0EFBE4786h, 00FC19DC6h, 0240CA1CCh
    DWORD 02DE92C6Fh, 04A7484AAh, 05CB0A9DCh, 076F988DAh
    DWORD 0983E5152h, 0A831C66Dh, 0B00327C8h, 0BF597FC7h
    DWORD 0C6E00BF3h, 0D5A79147h, 006CA6351h, 014292967h
    DWORD 027B70A85h, 02E1B2138h, 04D2C6DFCh, 053380D13h
    DWORD 0650A7354h, 0766A0ABBh, 081C2C92Eh, 092722C85h
    DWORD 0A2BFE8A1h, 0A81A664Bh, 0C24B8B70h, 0C76C51A3h
    DWORD 0D192E819h, 0D6990624h, 0F40E3585h, 0106AA070h
    DWORD 019A4C116h, 01E376C08h, 02748774Ch, 034B0BCB5h
    DWORD 0391C0CB3h, 04ED8AA4Ah, 05B9CCA4Fh, 0682E6FF3h
    DWORD 0748F82EEh, 078A5636Fh, 084C87814h, 08CC70208h
    DWORD 090BEFFFAh, 0A4506CEBh, 0BEF9A3F7h, 0C67178F2h

shaIV DWORD 06A09E667h, 0BB67AE85h, 03C6EF372h, 0A54FF53Ah
    DWORD 0510E527Fh, 09B05688Ch, 01F83D9ABh, 05BE0CD19h

shaBufLen DWORD 0
shaTotLo DWORD 0
shaTotHi DWORD 0
shaBitLo DWORD 0
shaBitHi DWORD 0

scanMode DWORD 0
verbose DWORD 1
depth DWORD 0
baseCount DWORD 0
hashFailed DWORD 0
textLen DWORD 0
logLen DWORD 0
passCount DWORD 0
tamperCount DWORD 0
missCount DWORD 0
newCount DWORD 0

.data?
shaBlock BYTE 64 DUP(?)
shaW DWORD 64 DUP(?)
shaH DWORD 8 DUP(?)
shaV DWORD 8 DUP(?)
sv_a TEXTEQU <shaV[0]>
sv_b TEXTEQU <shaV[4]>
sv_c TEXTEQU <shaV[8]>
sv_d TEXTEQU <shaV[12]>
sv_e TEXTEQU <shaV[16]>
sv_f TEXTEQU <shaV[20]>
sv_g TEXTEQU <shaV[24]>
sv_h TEXTEQU <shaV[28]>
curDigest BYTE 32 DUP(?)
innerDigest BYTE 32 DUP(?)
macDigest BYTE 32 DUP(?)
padBlk BYTE 64 DUP(?)
macHex BYTE 72 DUP(?)
hexBuf BYTE 72 DUP(?)
sigBuf BYTE 128 DUP(?)
fileBuf BYTE BUF_SIZE DUP(?)
baseText BYTE BASE_TEXT_MAX DUP(?)
baseDB BYTE MAX_FILES*ENTRY_SIZE DUP(?)
histBuf BYTE HIST_MAX+8 DUP(?)

.code

Sha256Init PROC
    push eax
    push ecx
    push esi
    push edi
    mov esi, OFFSET shaIV
    mov edi, OFFSET shaH
    mov ecx, 8
    rep movsd
    mov shaBufLen, 0
    mov shaTotLo, 0
    mov shaTotHi, 0
    pop edi
    pop esi
    pop ecx
    pop eax
    ret
Sha256Init ENDP

Sha256PutByte PROC
    push ebx
    mov ebx, shaBufLen
    mov shaBlock[ebx], al
    inc ebx
    mov shaBufLen, ebx
    cmp ebx, 64
    jb pb_return
    call Sha256Transform
    mov shaBufLen, 0
pb_return:
    pop ebx
    ret
Sha256PutByte ENDP

Sha256Update PROC
    push eax
    push ecx
    push esi
    add shaTotLo, ecx
    adc shaTotHi, 0
    jecxz su_done
su_loop:
    mov al, [esi]
    call Sha256PutByte
    inc esi
    dec ecx
    jnz su_loop
su_done:
    pop esi
    pop ecx
    pop eax
    ret
Sha256Update ENDP

Sha256Transform PROC
    pushad

    mov esi, OFFSET shaBlock
    mov edi, OFFSET shaW
    mov ecx, 16
tr_load:
    mov eax, [esi]
    bswap eax
    mov [edi], eax
    add esi, 4
    add edi, 4
    loop tr_load

    mov ebx, 16
tr_sched:
    mov eax, shaW[ebx*4-60]
    mov ecx, eax
    mov edx, eax
    ror eax, 7
    ror ecx, 18
    shr edx, 3
    xor eax, ecx
    xor eax, edx
    mov esi, eax
    mov eax, shaW[ebx*4-8]
    mov ecx, eax
    mov edx, eax
    ror eax, 17
    ror ecx, 19
    shr edx, 10
    xor eax, ecx
    xor eax, edx
    add eax, esi
    add eax, shaW[ebx*4-64]
    add eax, shaW[ebx*4-28]
    mov shaW[ebx*4], eax
    inc ebx
    cmp ebx, 64
    jb tr_sched

    mov esi, OFFSET shaH
    mov edi, OFFSET shaV
    mov ecx, 8
    rep movsd

    xor ebx, ebx
tr_round:
    mov eax, sv_e
    mov ecx, eax
    mov edx, eax
    ror eax, 6
    ror ecx, 11
    ror edx, 25
    xor eax, ecx
    xor eax, edx
    add eax, sv_h
    mov ecx, sv_e
    and ecx, sv_f
    mov edx, sv_e
    not edx
    and edx, sv_g
    xor ecx, edx
    add eax, ecx
    add eax, K256[ebx*4]
    add eax, shaW[ebx*4]
    mov esi, eax
    mov eax, sv_a
    mov ecx, eax
    mov edx, eax
    ror eax, 2
    ror ecx, 13
    ror edx, 22
    xor eax, ecx
    xor eax, edx
    mov ecx, sv_a
    and ecx, sv_b
    mov edx, sv_a
    and edx, sv_c
    xor ecx, edx
    mov edx, sv_b
    and edx, sv_c
    xor ecx, edx
    add eax, ecx
    mov ecx, sv_g
    mov sv_h, ecx
    mov ecx, sv_f
    mov sv_g, ecx
    mov ecx, sv_e
    mov sv_f, ecx
    mov ecx, sv_d
    add ecx, esi
    mov sv_e, ecx
    mov ecx, sv_c
    mov sv_d, ecx
    mov ecx, sv_b
    mov sv_c, ecx
    mov ecx, sv_a
    mov sv_b, ecx
    add eax, esi
    mov sv_a, eax
    inc ebx
    cmp ebx, 64
    jb tr_round

    xor ecx, ecx
tr_add:
    mov eax, shaV[ecx*4]
    add shaH[ecx*4], eax
    inc ecx
    cmp ecx, 8
    jb tr_add

    popad
    ret
Sha256Transform ENDP

Sha256Final PROC
    pushad
    mov eax, shaTotLo
    mov edx, shaTotHi
    shld edx, eax, 3
    shl eax, 3
    mov shaBitLo, eax
    mov shaBitHi, edx

    mov al, 80h
    call Sha256PutByte
fin_pad:
    cmp shaBufLen, 56
    je fin_len
    xor al, al
    call Sha256PutByte
    jmp fin_pad
fin_len:
    mov eax, shaBitHi
    bswap eax
    mov DWORD PTR shaBlock[56], eax
    mov eax, shaBitLo
    bswap eax
    mov DWORD PTR shaBlock[60], eax
    call Sha256Transform

    mov esi, OFFSET shaH
    mov ecx, 8
fin_out:
    mov eax, [esi]
    bswap eax
    mov [edi], eax
    add esi, 4
    add edi, 4
    loop fin_out
    popad
    ret
Sha256Final ENDP

XorPad64 PROC
    push ecx
    push esi
    mov esi, OFFSET padBlk
    mov ecx, 64
xp_loop:
    xor [esi], bl
    inc esi
    loop xp_loop
    pop esi
    pop ecx
    ret
XorPad64 ENDP

HmacSha256 PROC USES eax ebx ecx esi edi, msgPtr:PTR BYTE, msgLen:DWORD, outPtr:PTR BYTE
    cld
    mov edi, OFFSET padBlk
    xor eax, eax
    mov ecx, 16
    rep stosd
    mov esi, OFFSET hmacKey
    mov edi, OFFSET padBlk
    mov ecx, LENGTHOF hmacKey - 1
    rep movsb

    mov bl, 36h
    call XorPad64
    call Sha256Init
    mov esi, OFFSET padBlk
    mov ecx, 64
    call Sha256Update
    mov esi, msgPtr
    mov ecx, msgLen
    call Sha256Update
    mov edi, OFFSET innerDigest
    call Sha256Final

    mov bl, 6Ah
    call XorPad64
    call Sha256Init
    mov esi, OFFSET padBlk
    mov ecx, 64
    call Sha256Update
    mov esi, OFFSET innerDigest
    mov ecx, 32
    call Sha256Update
    mov edi, outPtr
    call Sha256Final
    ret
HmacSha256 ENDP

StrLen PROC
    xor eax, eax
sl_loop:
    cmp BYTE PTR [esi+eax], 0
    je sl_done
    inc eax
    jmp sl_loop
sl_done:
    ret
StrLen ENDP

AppendStr PROC
as_loop:
    mov al, [esi]
    test al, al
    jz as_done
    mov [edi], al
    inc esi
    inc edi
    jmp as_loop
as_done:
    ret
AppendStr ENDP

DigestToHex PROC
    push eax
    push ecx
    push edx
    mov ecx, 32
dh_loop:
    movzx eax, BYTE PTR [esi]
    mov edx, eax
    shr edx, 4
    mov dl, hexTable[edx]
    mov [edi], dl
    and eax, 0Fh
    mov al, hexTable[eax]
    mov [edi+1], al
    add edi, 2
    inc esi
    dec ecx
    jnz dh_loop
    pop edx
    pop ecx
    pop eax
    ret
DigestToHex ENDP

HexVal PROC
    cmp al, '9'
    jbe hv_digit
    cmp al, 'F'
    jbe hv_upper
    sub al, 'a' - 10
    ret
hv_upper:
    sub al, 'A' - 10
    ret
hv_digit:
    sub al, '0'
    ret
HexVal ENDP

PutDec PROC
    push ebx
    push edx
    push esi
    add edi, ecx
    mov esi, edi
    mov ebx, 10
pd_loop:
    xor edx, edx
    div ebx
    add dl, '0'
    dec edi
    mov [edi], dl
    dec ecx
    jnz pd_loop
    mov edi, esi
    pop esi
    pop edx
    pop ebx
    ret
PutDec ENDP

PrintPadded PROC USES eax ecx edx esi, pathPtr:PTR BYTE
    mov edx, pathPtr
    call WriteString
    mov esi, pathPtr
    call StrLen
    mov ecx, 44
    sub ecx, eax
    jg pp_pad
    mov ecx, 1
pp_pad:
    mov al, ' '
    call WriteChar
    dec ecx
    jnz pp_pad
    ret
PrintPadded ENDP

ReadWholeFile PROC USES ebx, namePtr:PTR BYTE, bufPtr:PTR BYTE, maxLen:DWORD
    LOCAL hFile:DWORD, nRead:DWORD
    INVOKE CreateFileA, namePtr, ACC_READ, SHARE_RW, 0, MODE_OPEN, ATTR_NORMAL, 0
    cmp eax, BAD_HANDLE
    je rw_fail
    mov hFile, eax
    mov nRead, 0
    INVOKE ReadFile, hFile, bufPtr, maxLen, ADDR nRead, 0
    mov ebx, eax
    INVOKE CloseHandle, hFile
    test ebx, ebx
    jz rw_fail
    mov eax, nRead
    clc
    ret
rw_fail:
    xor eax, eax
    stc
    ret
ReadWholeFile ENDP

SaveFile PROC USES ebx, namePtr:PTR BYTE, bufPtr:PTR BYTE, dataLen:DWORD, accMode:DWORD, dispMode:DWORD
    LOCAL hFile:DWORD, nWritten:DWORD
    INVOKE CreateFileA, namePtr, accMode, SHARE_R, 0, dispMode, ATTR_NORMAL, 0
    cmp eax, BAD_HANDLE
    je sf_fail
    mov hFile, eax
    mov nWritten, 0
    INVOKE WriteFile, hFile, bufPtr, dataLen, ADDR nWritten, 0
    mov ebx, eax
    INVOKE CloseHandle, hFile
    test ebx, ebx
    jz sf_fail
    clc
    ret
sf_fail:
    stc
    ret
SaveFile ENDP

LogEvent PROC USES eax ecx edx esi edi, evPtr:PTR BYTE, pathPtr:PTR BYTE
    LOCAL sysTime[16]:BYTE
    LOCAL logLine[400]:BYTE

    INVOKE GetLocalTime, ADDR sysTime

    lea edi, logLine
    movzx eax, WORD PTR sysTime[0]
    mov ecx, 4
    call PutDec
    mov BYTE PTR [edi], '-'
    inc edi
    movzx eax, WORD PTR sysTime[2]
    mov ecx, 2
    call PutDec
    mov BYTE PTR [edi], '-'
    inc edi
    movzx eax, WORD PTR sysTime[6]
    mov ecx, 2
    call PutDec
    mov BYTE PTR [edi], ' '
    inc edi
    movzx eax, WORD PTR sysTime[8]
    mov ecx, 2
    call PutDec
    mov BYTE PTR [edi], ':'
    inc edi
    movzx eax, WORD PTR sysTime[10]
    mov ecx, 2
    call PutDec
    mov BYTE PTR [edi], ':'
    inc edi
    movzx eax, WORD PTR sysTime[12]
    mov ecx, 2
    call PutDec

    mov esi, OFFSET sepStr
    call AppendStr
    mov esi, evPtr
    call AppendStr
    mov esi, OFFSET sepStr
    call AppendStr
    mov esi, pathPtr
    call AppendStr
    mov BYTE PTR [edi], 0Dh
    mov BYTE PTR [edi+1], 0Ah
    add edi, 2

    lea eax, logLine
    sub edi, eax
    mov logLen, edi
    INVOKE SaveFile, ADDR logName, ADDR logLine, logLen, ACC_APPEND, MODE_ALWAYS
    ret
LogEvent ENDP

PrintStatus PROC USES eax ebx ecx edx esi edi, pathPtr:PTR BYTE, stCode:DWORD
    mov eax, C_WHITE
    call SetTextColor
    INVOKE PrintPadded, pathPtr
    mov ebx, stCode
    mov eax, stColor[ebx*4]
    call SetTextColor
    mov edx, stMsg[ebx*4]
    call WriteString
    mov eax, C_WHITE
    call SetTextColor
    call Crlf
    ret
PrintStatus ENDP

ReportEvent PROC USES eax ebx ecx edx esi edi, pathPtr:PTR BYTE, stCode:DWORD
    INVOKE PrintStatus, pathPtr, stCode
    mov ebx, stCode
    cmp ebx, ST_PASS
    je re_done
    mov eax, stEvt[ebx*4]
    INVOKE LogEvent, eax, pathPtr
re_done:
    ret
ReportEvent ENDP

ParseBaseline PROC USES eax ebx ecx edx esi edi
    mov baseCount, 0
    mov esi, OFFSET baseText
ps_skip:
    mov al, [esi]
    test al, al
    jz ps_done
    cmp al, 0Dh
    je ps_adv
    cmp al, 0Ah
    je ps_adv
    jmp ps_line
ps_adv:
    inc esi
    jmp ps_skip
ps_line:
    cmp baseCount, MAX_FILES
    jae ps_done
    mov edx, esi
ps_eol:
    mov al, [edx]
    test al, al
    jz ps_eolf
    cmp al, 0Dh
    je ps_eolf
    cmp al, 0Ah
    je ps_eolf
    inc edx
    jmp ps_eol
ps_eolf:
    mov ecx, edx
    sub ecx, esi
    cmp ecx, 68
    jb ps_done
    sub ecx, 67
    cmp ecx, 259
    ja ps_done
    cmp BYTE PTR [esi+ecx], ' '
    jne ps_done
    cmp BYTE PTR [esi+ecx+1], '|'
    jne ps_done

    mov eax, baseCount
    imul eax, ENTRY_SIZE
    add eax, OFFSET baseDB
    mov ebx, eax
    mov edi, ebx
    rep movsb
    mov BYTE PTR [edi], 0
    add esi, 3

    lea edi, [ebx + E_HASH]
    mov ecx, 32
ps_hex:
    mov al, [esi]
    call HexVal
    shl al, 4
    mov dl, al
    mov al, [esi+1]
    call HexVal
    or al, dl
    mov [edi], al
    add esi, 2
    inc edi
    dec ecx
    jnz ps_hex

    mov DWORD PTR [ebx + E_SEEN], 0
    mov DWORD PTR [ebx + E_STATE], ST_PASS
    mov DWORD PTR [ebx + E_ORIGIN], 0
    inc baseCount
    jmp ps_skip
ps_done:
    ret
ParseBaseline ENDP

LoadAndVerifyBaseline PROC USES eax ecx esi edi
    INVOKE ReadWholeFile, ADDR baselineName, ADDR baseText, BASE_TEXT_MAX-1
    jc lv_nobase
    mov textLen, eax
    mov BYTE PTR baseText[eax], 0

    INVOKE ReadWholeFile, ADDR sigName, ADDR sigBuf, 64
    jc lv_broken
    cmp eax, 64
    jne lv_broken

    INVOKE HmacSha256, ADDR baseText, textLen, ADDR macDigest
    mov esi, OFFSET macDigest
    mov edi, OFFSET macHex
    call DigestToHex

    mov esi, OFFSET macHex
    mov edi, OFFSET sigBuf
    mov ecx, 64
    repe cmpsb
    jne lv_broken

    call ParseBaseline
    clc
    ret

lv_nobase:
    mov eax, C_RED
    call SetTextColor
    mov edx, OFFSET msgNoBase
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    stc
    ret

lv_broken:
    mov eax, C_RED
    call SetTextColor
    mov edx, OFFSET msgBroken
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    INVOKE LogEvent, ADDR evAlert, ADDR baselineName
    stc
    ret
LoadAndVerifyBaseline ENDP

HashFileSHA PROC USES ebx ecx edx esi edi, pathPtr:PTR BYTE
    LOCAL hFile:DWORD, nRead:DWORD
    INVOKE CreateFileA, pathPtr, ACC_READ, SHARE_RW, 0, MODE_OPEN, ATTR_NORMAL, 0
    cmp eax, BAD_HANDLE
    je hs_fail
    mov hFile, eax
    call Sha256Init
hs_read:
    mov nRead, 0
    INVOKE ReadFile, hFile, OFFSET fileBuf, BUF_SIZE, ADDR nRead, 0
    test eax, eax
    jz hs_err
    cmp nRead, 0
    je hs_done
    mov esi, OFFSET fileBuf
    mov ecx, nRead
    call Sha256Update
    jmp hs_read
hs_done:
    INVOKE CloseHandle, hFile
    mov edi, OFFSET curDigest
    call Sha256Final
    clc
    ret
hs_err:
    INVOKE CloseHandle, hFile
hs_fail:
    stc
    ret
HashFileSHA ENDP

FindEntry PROC USES ebx ecx esi edi, pathPtr:PTR BYTE
    mov ebx, OFFSET baseDB
    mov ecx, baseCount
    test ecx, ecx
    jz fe_none
fe_loop:
    mov esi, pathPtr
    mov edi, ebx
fe_cmp:
    mov al, [esi]
    cmp al, [edi]
    jne fe_next
    test al, al
    jz fe_found
    inc esi
    inc edi
    jmp fe_cmp
fe_next:
    add ebx, ENTRY_SIZE
    dec ecx
    jnz fe_loop
fe_none:
    xor eax, eax
    ret
fe_found:
    mov eax, ebx
    ret
FindEntry ENDP

ProcessFile PROC USES ebx ecx edx esi edi, pathPtr:PTR BYTE
    mov hashFailed, 0
    INVOKE HashFileSHA, pathPtr
    jnc pf_hashed
    mov hashFailed, 1
pf_hashed:
    cmp scanMode, 0
    je pf_baseline

    INVOKE FindEntry, pathPtr
    mov ebx, eax
    cmp hashFailed, 0
    jne pf_locked
    test ebx, ebx
    jz pf_new

    mov DWORD PTR [ebx + E_SEEN], 1
    mov esi, OFFSET curDigest
    lea edi, [ebx + E_HASH]
    mov ecx, 8
    repe cmpsd
    jne pf_diff
    mov eax, ST_PASS
    cmp DWORD PTR [ebx + E_ORIGIN], 1
    jne pf_state
    mov eax, ST_NEW
    jmp pf_state
pf_diff:
    mov eax, ST_TAMPER
pf_state:
    cmp eax, ST_PASS
    jne pf_t1
    inc passCount
    jmp pf_tally_done
pf_t1:
    cmp eax, ST_TAMPER
    jne pf_t2
    inc tamperCount
    jmp pf_tally_done
pf_t2:
    inc newCount
pf_tally_done:
    cmp eax, [ebx + E_STATE]
    je pf_same
    mov [ebx + E_STATE], eax
    mov edx, ST_RESTORED
    cmp eax, ST_TAMPER
    jne pf_rep
    mov edx, ST_TAMPER
pf_rep:
    INVOKE ReportEvent, pathPtr, edx
    cmp DWORD PTR [ebx + E_STATE], ST_TAMPER
    jne pf_done
    mov eax, C_WHITE
    call SetTextColor
    mov edx, OFFSET msgWas
    call WriteString
    mov eax, DWORD PTR [ebx + E_HASH]
    bswap eax
    call WriteHex
    mov edx, OFFSET msgNow
    call WriteString
    mov eax, DWORD PTR curDigest
    bswap eax
    call WriteHex
    mov edx, OFFSET msgDots2
    call WriteString
    call Crlf
    jmp pf_done

pf_same:
    cmp verbose, 0
    je pf_done
    INVOKE PrintStatus, pathPtr, eax
    jmp pf_done

pf_locked:
    test ebx, ebx
    jz pf_done
    mov DWORD PTR [ebx + E_SEEN], 1
    cmp verbose, 0
    je pf_done
    INVOKE PrintStatus, pathPtr, ST_LOCKED
    jmp pf_done

pf_new:
    inc newCount
    INVOKE ReportEvent, pathPtr, ST_NEW
    cmp baseCount, MAX_FILES
    jae pf_done
    mov eax, baseCount
    imul eax, ENTRY_SIZE
    add eax, OFFSET baseDB
    mov ebx, eax
    mov edi, ebx
    mov esi, pathPtr
    call AppendStr
    mov BYTE PTR [edi], 0
    mov esi, OFFSET curDigest
    lea edi, [ebx + E_HASH]
    mov ecx, 8
    rep movsd
    mov DWORD PTR [ebx + E_SEEN], 1
    mov DWORD PTR [ebx + E_STATE], ST_NEW
    mov DWORD PTR [ebx + E_ORIGIN], 1
    inc baseCount
    jmp pf_done

pf_baseline:
    cmp hashFailed, 0
    jne pf_blocked
    cmp baseCount, MAX_FILES
    jae pf_full
    mov eax, baseCount
    imul eax, ENTRY_SIZE
    add eax, OFFSET baseDB
    mov ebx, eax
    mov edi, ebx
    mov esi, pathPtr
    call AppendStr
    mov BYTE PTR [edi], 0
    mov esi, OFFSET curDigest
    lea edi, [ebx + E_HASH]
    mov ecx, 8
    rep movsd
    mov DWORD PTR [ebx + E_SEEN], 0
    mov DWORD PTR [ebx + E_STATE], ST_PASS
    mov DWORD PTR [ebx + E_ORIGIN], 0
    inc baseCount

    mov eax, C_WHITE
    call SetTextColor
    INVOKE PrintPadded, pathPtr
    mov eax, C_GREEN
    call SetTextColor
    mov edx, OFFSET msgHashed
    call WriteString
    mov esi, OFFSET curDigest
    mov edi, OFFSET hexBuf
    call DigestToHex
    mov BYTE PTR hexBuf[16], 0
    mov edx, OFFSET hexBuf
    call WriteString
    mov edx, OFFSET msgDots
    call WriteString
    mov eax, C_WHITE
    call SetTextColor
    call Crlf
    jmp pf_done
pf_blocked:
    INVOKE PrintStatus, pathPtr, ST_LOCKED
    jmp pf_done
pf_full:
    mov eax, C_YELLOW
    call SetTextColor
    mov edx, OFFSET msgFull
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
pf_done:
    ret
ProcessFile ENDP

ScanDir PROC USES ebx esi edi, dirPtr:PTR BYTE
    LOCAL hFind:DWORD
    LOCAL fd[320]:BYTE
    LOCAL fullPath[288]:BYTE

    cmp depth, MAX_DEPTH
    jae sd_exit
    inc depth

    lea edi, fullPath
    mov esi, dirPtr
    call AppendStr
    mov esi, OFFSET starStr
    call AppendStr
    mov BYTE PTR [edi], 0

    INVOKE FindFirstFileA, ADDR fullPath, ADDR fd
    cmp eax, BAD_HANDLE
    je sd_leave
    mov hFind, eax

sd_entry:
    lea esi, fd
    add esi, F_NAME
    cmp BYTE PTR [esi], '.'
    jne sd_real
    cmp BYTE PTR [esi+1], 0
    je sd_advance
    cmp BYTE PTR [esi+1], '.'
    jne sd_real
    cmp BYTE PTR [esi+2], 0
    je sd_advance
sd_real:
    mov eax, DWORD PTR fd[F_ATTR]
    test eax, ATTR_REPARSE
    jnz sd_advance

    mov esi, dirPtr
    call StrLen
    mov ebx, eax
    lea esi, fd
    add esi, F_NAME
    call StrLen
    add eax, ebx
    inc eax
    cmp eax, 259
    ja sd_advance

    lea edi, fullPath
    mov esi, dirPtr
    call AppendStr
    mov BYTE PTR [edi], '\'
    inc edi
    lea esi, fd
    add esi, F_NAME
    call AppendStr
    mov BYTE PTR [edi], 0

    mov eax, DWORD PTR fd[F_ATTR]
    test eax, ATTR_DIR
    jnz sd_isdir
    INVOKE ProcessFile, ADDR fullPath
    jmp sd_advance
sd_isdir:
    INVOKE ScanDir, ADDR fullPath

sd_advance:
    INVOKE FindNextFileA, hFind, ADDR fd
    test eax, eax
    jnz sd_entry
    INVOKE FindClose, hFind
sd_leave:
    dec depth
sd_exit:
    ret
ScanDir ENDP

ScanOnce PROC USES eax ebx ecx
    mov ebx, OFFSET baseDB
    mov ecx, baseCount
    jecxz so_scan
so_clear:
    mov DWORD PTR [ebx + E_SEEN], 0
    add ebx, ENTRY_SIZE
    dec ecx
    jnz so_clear
so_scan:
    mov depth, 0
    INVOKE ScanDir, ADDR rootDir

    mov ebx, OFFSET baseDB
    mov ecx, baseCount
    jecxz so_done
so_check:
    cmp DWORD PTR [ebx + E_SEEN], 0
    jne so_next
    inc missCount
    cmp DWORD PTR [ebx + E_STATE], ST_MISSING
    je so_next
    mov DWORD PTR [ebx + E_STATE], ST_MISSING
    INVOKE ReportEvent, ebx, ST_MISSING
so_next:
    add ebx, ENTRY_SIZE
    dec ecx
    jnz so_check
so_done:
    ret
ScanOnce ENDP

InitBaseline PROC USES eax ebx ecx edx esi edi
    call Crlf
    INVOKE ReadWholeFile, ADDR baselineName, ADDR sigBuf, 1
    jc ib_go
    mov eax, C_YELLOW
    call SetTextColor
    mov edx, OFFSET msgOverwrite
    call WriteString
    call ReadChar
    call WriteChar
    call Crlf
    mov ebx, eax
    mov eax, C_WHITE
    call SetTextColor
    or bl, 20h
    cmp bl, 'y'
    je ib_go
    mov edx, OFFSET msgCancelled
    call WriteString
    call Crlf
    jmp ib_exit

ib_go:
    mov eax, C_WHITE
    call SetTextColor
    mov edx, OFFSET msgInitHdr
    call WriteString
    call Crlf
    call Crlf
    mov baseCount, 0
    mov scanMode, 0
    mov verbose, 1
    mov depth, 0
    INVOKE ScanDir, ADDR rootDir

    cmp baseCount, 0
    jne ib_build
    mov eax, C_YELLOW
    call SetTextColor
    mov edx, OFFSET msgEmpty
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    jmp ib_exit

ib_build:
    mov edi, OFFSET baseText
    mov ebx, OFFSET baseDB
    mov ecx, baseCount
ib_line:
    mov esi, ebx
    call AppendStr
    mov esi, OFFSET sepStr
    call AppendStr
    lea esi, [ebx + E_HASH]
    call DigestToHex
    mov BYTE PTR [edi], 0Dh
    mov BYTE PTR [edi+1], 0Ah
    add edi, 2
    add ebx, ENTRY_SIZE
    dec ecx
    jnz ib_line
    mov eax, edi
    sub eax, OFFSET baseText
    mov textLen, eax

    INVOKE SaveFile, ADDR baselineName, ADDR baseText, textLen, ACC_WRITE, MODE_CREATE
    jc ib_err
    INVOKE HmacSha256, ADDR baseText, textLen, ADDR macDigest
    mov esi, OFFSET macDigest
    mov edi, OFFSET macHex
    call DigestToHex
    INVOKE SaveFile, ADDR sigName, ADDR macHex, 64, ACC_WRITE, MODE_CREATE
    jc ib_err

    INVOKE LogEvent, ADDR evBaseline, ADDR rootDir
    call Crlf
    mov eax, C_CYAN
    call SetTextColor
    mov edx, OFFSET msgSealed
    call WriteString
    call Crlf
    jmp ib_reset
ib_err:
    mov eax, C_RED
    call SetTextColor
    mov edx, OFFSET msgSaveErr
    call WriteString
    call Crlf
ib_reset:
    mov eax, C_WHITE
    call SetTextColor
ib_exit:
    ret
InitBaseline ENDP

RunCheck PROC USES eax edx
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    mov edx, OFFSET msgCheckHdr
    call WriteString
    call Crlf
    call Crlf
    call LoadAndVerifyBaseline
    jc rc_exit
    mov scanMode, 1
    mov verbose, 1
    mov passCount, 0
    mov tamperCount, 0
    mov missCount, 0
    mov newCount, 0
    call ScanOnce

    call Crlf
    mov edx, OFFSET msgSumPass
    call WriteString
    mov eax, passCount
    call WriteDec
    mov edx, OFFSET msgSumTam
    call WriteString
    mov eax, tamperCount
    call WriteDec
    mov edx, OFFSET msgSumMis
    call WriteString
    mov eax, missCount
    call WriteDec
    mov edx, OFFSET msgSumNew
    call WriteString
    mov eax, newCount
    call WriteDec
    call Crlf
    mov eax, tamperCount
    or eax, missCount
    or eax, newCount
    jnz rc_exit
    mov eax, C_GREEN
    call SetTextColor
    mov edx, OFFSET msgAllOk
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    INVOKE LogEvent, ADDR evVerified, ADDR rootDir
rc_exit:
    ret
RunCheck ENDP

RealTimeMonitor PROC USES eax edx
    LOCAL hNotify:DWORD
    call Crlf
    mov eax, C_CYAN
    call SetTextColor
    mov edx, OFFSET msgMonHdr
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    call Crlf
    call LoadAndVerifyBaseline
    jc rm_exit

    mov scanMode, 1
    mov verbose, 1
    mov passCount, 0
    mov tamperCount, 0
    mov missCount, 0
    mov newCount, 0
    call ScanOnce

    INVOKE FindFirstChangeNotificationA, OFFSET rootDir, 1, NOTIFY_FILTER
    cmp eax, BAD_HANDLE
    je rm_nohandle
    mov hNotify, eax

    call Crlf
    mov eax, C_CYAN
    call SetTextColor
    mov edx, OFFSET msgWatching
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    INVOKE LogEvent, ADDR evWatch, ADDR rootDir
    mov verbose, 0

rm_loop:
    INVOKE WaitForSingleObject, hNotify, 400
    test eax, eax
    jz rm_changed
    cmp eax, 102h
    je rm_key
    jmp rm_stop
rm_changed:
    INVOKE Sleep, 300
    INVOKE FindNextChangeNotification, hNotify
    call ScanOnce
rm_key:
    call ReadKey
    jz rm_loop

rm_stop:
    INVOKE FindCloseChangeNotification, hNotify
    INVOKE LogEvent, ADDR evWatch, ADDR rootDir
    call Crlf
    mov edx, OFFSET msgStopped
    call WriteString
    call Crlf
    jmp rm_exit
rm_nohandle:
    mov eax, C_RED
    call SetTextColor
    mov edx, OFFSET msgNoNotify
    call WriteString
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
rm_exit:
    ret
RealTimeMonitor ENDP

EventColor PROC
    mov eax, C_RED
    cmp dl, 'T'
    je ec_ret
    cmp dl, 'A'
    je ec_ret
    mov eax, C_YELLOW
    cmp dl, 'M'
    je ec_ret
    cmp dl, 'N'
    je ec_ret
    cmp dl, 'L'
    je ec_ret
    mov eax, C_CYAN
    cmp dl, 'B'
    je ec_ret
    cmp dl, 'W'
    je ec_ret
    mov eax, C_GREEN
    cmp dl, 'V'
    je ec_ret
    cmp dl, 'R'
    je ec_ret
    mov eax, C_WHITE
ec_ret:
    ret
EventColor ENDP

ShowHistory PROC USES eax ebx ecx edx esi edi
    LOCAL hFile:DWORD, nRead:DWORD
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    mov edx, OFFSET msgHistHdr
    call WriteString
    call Crlf
    call Crlf

    INVOKE CreateFileA, OFFSET logName, ACC_READ, SHARE_RW, 0, MODE_OPEN, ATTR_NORMAL, 0
    cmp eax, BAD_HANDLE
    je sh_none
    mov hFile, eax

    xor ebx, ebx
    INVOKE GetFileSize, hFile, 0
    cmp eax, HIST_MAX
    jbe sh_read
    sub eax, HIST_MAX
    INVOKE SetFilePointer, hFile, eax, 0, 0
    mov ebx, 1
sh_read:
    mov nRead, 0
    INVOKE ReadFile, hFile, OFFSET histBuf, HIST_MAX, ADDR nRead, 0
    INVOKE CloseHandle, hFile
    mov eax, nRead
    mov BYTE PTR histBuf[eax], 0
    mov esi, OFFSET histBuf
    test ebx, ebx
    jz sh_next
sh_skip1:
    mov al, [esi]
    test al, al
    jz sh_end
    inc esi
    cmp al, 0Ah
    jne sh_skip1

sh_next:
    mov al, [esi]
    test al, al
    jz sh_end
    cmp al, 0Dh
    je sh_adv
    cmp al, 0Ah
    je sh_adv
    mov edi, esi
sh_eol:
    mov al, [edi]
    test al, al
    jz sh_have
    cmp al, 0Dh
    je sh_have
    cmp al, 0Ah
    je sh_have
    inc edi
    jmp sh_eol
sh_have:
    mov bl, [edi]
    mov BYTE PTR [edi], 0
    mov eax, C_WHITE
    mov ecx, edi
    sub ecx, esi
    cmp ecx, 23
    jb sh_print
    movzx edx, BYTE PTR [esi+22]
    call EventColor
sh_print:
    call SetTextColor
    mov edx, esi
    call WriteString
    call Crlf
    mov [edi], bl
    mov esi, edi
    jmp sh_next
sh_adv:
    inc esi
    jmp sh_next
sh_end:
    mov eax, C_WHITE
    call SetTextColor
    jmp sh_exit
sh_none:
    mov edx, OFFSET msgNoHist
    call WriteString
    call Crlf
sh_exit:
    ret
ShowHistory ENDP

ShowMenu PROC USES eax edx
    mov eax, C_CYAN
    call SetTextColor
    mov edx, OFFSET msgTitle
    call WriteString
    call Crlf
    call Crlf
    mov eax, C_WHITE
    call SetTextColor
    mov edx, OFFSET msgOpt1
    call WriteString
    call Crlf
    mov edx, OFFSET msgOpt2
    call WriteString
    call Crlf
    mov edx, OFFSET msgOpt3
    call WriteString
    call Crlf
    mov edx, OFFSET msgOpt4
    call WriteString
    call Crlf
    mov edx, OFFSET msgOpt5
    call WriteString
    call Crlf
    call Crlf
    mov edx, OFFSET msgPrompt
    call WriteString
    ret
ShowMenu ENDP

main PROC
menu_loop:
    call Clrscr
    call ShowMenu
    call ReadChar
    cmp al, '1'
    je do_init
    cmp al, '2'
    je do_check
    cmp al, '3'
    je do_monitor
    cmp al, '4'
    je do_hist
    cmp al, '5'
    je do_exit
    jmp menu_loop

do_init:
    call InitBaseline
    jmp do_pause
do_check:
    call RunCheck
    jmp do_pause
do_monitor:
    call RealTimeMonitor
    jmp do_pause
do_hist:
    call ShowHistory
do_pause:
    call Crlf
    call WaitMsg
    jmp menu_loop

do_exit:
    call Crlf
    mov edx, OFFSET msgBye
    call WriteString
    call Crlf
    exit
main ENDP

END main

