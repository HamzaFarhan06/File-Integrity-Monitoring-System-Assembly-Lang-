; =====================================================================
;  FIM_PRO.ASM  -  Assembly File Integrity Monitor (x86 MASM + Irvine32)
;
;  FEATURES
;    * Recursive directory scan          (FindFirstFileA / FindNextFileA)
;    * SHA-256 written from scratch      (rol/ror/shr/xor/and/not/add/bswap)
;    * HMAC-SHA256 "seal" on baseline    (baseline.sig protects baseline.txt)
;    * Persistent event history          (fim_history.log, timestamped)
;    * Real-time monitoring              (FindFirstChangeNotificationA)
;
;  FILES USED (all relative to the working directory)
;    monitored\      folder that is watched (create it, add sub-folders/files)
;    baseline.txt    "path | 64-hex SHA-256" one line per file
;    baseline.sig    HMAC-SHA256 of baseline.txt  (64 hex chars)
;    fim_history.log append-only event log
;
;  CODE MAP
;    Part 1  Constants, prototypes, data
;    Part 2  SHA-256 engine + HMAC
;    Part 3  Helpers: hex, strings, file I/O, event log
;    Part 4  Baseline load / verify
;    Part 5  Recursive scanner + per-file comparison
;    Part 6  Menu actions: baseline, check, monitor, history
;    Part 7  main
; =====================================================================
INCLUDE Irvine32.inc
INCLUDELIB kernel32.lib

; ---------------------------------------------------------------------
; Windows API imports, declared with PROTO (the standard MASM way).
;   These are __stdcall functions: kernel32.lib really stores them under
;   decorated names like "_FindFirstFileA@8". We do NOT write that
;   decoration ourselves - MASM's INVOKE mechanism adds it automatically
;   whenever a PROTO'd name is called with INVOKE, so the linker finds
;   the right symbol. (Calling these with raw PUSH/CALL and a manually
;   typed "@N" suffix looks similar but will NOT link, because the
;   symbol we'd be asking for is missing the leading underscore that
;   the real import library uses.) All params below are typed DWORD or
;   PTR BYTE only to keep the prototypes simple; Win32 handles, sizes
;   and pointers are all 4 bytes on x86, so this is completely safe.
; ---------------------------------------------------------------------
FindFirstFileA               PROTO :PTR BYTE, :PTR BYTE
FindNextFileA                PROTO :DWORD, :PTR BYTE
FindClose                    PROTO :DWORD
CreateFileA                  PROTO :PTR BYTE, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle                  PROTO :DWORD
GetFileSize                  PROTO :DWORD, :DWORD
FindFirstChangeNotificationA  PROTO :PTR BYTE, :DWORD, :DWORD
FindNextChangeNotification    PROTO :DWORD
FindCloseChangeNotification   PROTO :DWORD
WaitForSingleObject           PROTO :DWORD, :DWORD
Sleep                          PROTO :DWORD

; ---------------------------------------------------------------------
; Prototypes for our own procedures that are called with INVOKE
; ---------------------------------------------------------------------
ScanDir       PROTO, dirPtr:PTR BYTE
ProcessFile   PROTO, pathPtr:PTR BYTE
HashFileSHA   PROTO, pathPtr:PTR BYTE
FindEntry     PROTO, pathPtr:PTR BYTE
PrintStatus   PROTO, pathPtr:PTR BYTE, stCode:DWORD
ReportEvent   PROTO, pathPtr:PTR BYTE, stCode:DWORD
LogEvent      PROTO, evPtr:PTR BYTE, pathPtr:PTR BYTE
SaveFile      PROTO, namePtr:PTR BYTE, bufPtr:PTR BYTE, dataLen:DWORD, accMode:DWORD, dispMode:DWORD
ReadWholeFile PROTO, namePtr:PTR BYTE, bufPtr:PTR BYTE, maxLen:DWORD
HmacSha256    PROTO, msgPtr:PTR BYTE, msgLen:DWORD, outPtr:PTR BYTE
PrintPadded   PROTO, pathPtr:PTR BYTE

; =====================================================================
; PART 1 - CONSTANTS AND DATA
; =====================================================================
; ---- Win32 constants (own names, so they never clash with Irvine's) ----
ACC_READ      EQU 80000000h     ; GENERIC_READ
ACC_WRITE     EQU 40000000h     ; GENERIC_WRITE
ACC_APPEND    EQU 00000004h     ; FILE_APPEND_DATA (writes always go to EOF)
SHARE_RW      EQU 3             ; let other programs read/write while we read
SHARE_R       EQU 1
MODE_CREATE   EQU 2             ; CREATE_ALWAYS  (overwrite)
MODE_OPEN     EQU 3             ; OPEN_EXISTING
MODE_ALWAYS   EQU 4             ; OPEN_ALWAYS   (create if missing)
ATTR_NORMAL   EQU 80h
ATTR_DIR      EQU 10h           ; FILE_ATTRIBUTE_DIRECTORY
ATTR_REPARSE  EQU 400h          ; symlink / junction (skipped, avoids loops)
BAD_HANDLE    EQU -1            ; INVALID_HANDLE_VALUE
NOTIFY_FILTER EQU 1Bh           ; file name | dir name | size | last write

; ---- WIN32_FIND_DATAA field offsets (the structure is 320 bytes) ----
F_ATTR        EQU 0
F_NAME        EQU 44            ; cFileName[260]

; ---- console colours (Irvine SetTextColor) ----
C_GREEN       EQU 10
C_RED         EQU 12
C_YELLOW      EQU 14
C_WHITE       EQU 15
C_CYAN        EQU 11

; ---- program limits ----
MAX_FILES     EQU 64            ; files tracked in memory
MAX_DEPTH     EQU 8             ; recursion guard for sub-folders
BUF_SIZE      EQU 4096          ; bytes read from a file per chunk
BASE_TEXT_MAX EQU 32768         ; max size of baseline.txt
HIST_MAX      EQU 3200          ; bytes of history shown on screen

; ---- one baseline "entry" in memory (ENTRY_SIZE = 304 bytes) ----
E_PATH        EQU 0             ; char[260]  file path
E_HASH        EQU 260           ; byte[32]   SHA-256 digest
E_SEEN        EQU 292           ; dword      found during current scan?
E_STATE       EQU 296           ; dword      last reported state (ST_*)
E_ORIGIN      EQU 300           ; dword      0 = from baseline, 1 = new file
ENTRY_SIZE    EQU 304

; ---- states / status codes ----
ST_PASS       EQU 0
ST_TAMPER     EQU 1
ST_MISSING    EQU 2
ST_NEW        EQU 3
ST_LOCKED     EQU 4
ST_RESTORED   EQU 5

.data
; ---- file / folder names ----
rootDir      BYTE "monitored",0
baselineName BYTE "baseline.txt",0
sigName      BYTE "baseline.sig",0
logName      BYTE "fim_history.log",0
starStr      BYTE "\*",0
sepStr       BYTE " | ",0
hmacKey      BYTE "FIM-Secret-Key-COAL-2026!",0     ; secret key for HMAC seal
hexTable     BYTE "0123456789ABCDEF"

; ---- event names written to the history log (all exactly 8 chars) ----
evTamper     BYTE "TAMPERED",0
evMissing    BYTE "MISSING ",0
evNew        BYTE "NEWFILE ",0
evLocked     BYTE "LOCKED  ",0
evRestored   BYTE "RESTORED",0
evBaseline   BYTE "BASELINE",0
evAlert      BYTE "ALERT   ",0
evWatch      BYTE "WATCH   ",0
evVerified   BYTE "VERIFIED",0

; ---- status messages (exact wording requested) ----
msgPass      BYTE "[PASS]  - Hash matches",0
msgTamper    BYTE "[TAMPERED]  - Hash mismatch detected!",0
msgMissing   BYTE "[MISSING]  - File not found!",0
msgNew       BYTE "[NEW]  - File is not in the baseline!",0
msgLocked    BYTE "[LOCKED]  - File cannot be opened!",0
msgRestored  BYTE "[RESTORED]  - Hash matches baseline again",0

; ---- lookup tables indexed by ST_* code (0..5) ----
stMsg    DWORD OFFSET msgPass, OFFSET msgTamper, OFFSET msgMissing
         DWORD OFFSET msgNew, OFFSET msgLocked, OFFSET msgRestored
stColor  DWORD C_GREEN, C_RED, C_YELLOW, C_YELLOW, C_YELLOW, C_GREEN
stEvt    DWORD 0, OFFSET evTamper, OFFSET evMissing
         DWORD OFFSET evNew, OFFSET evLocked, OFFSET evRestored

; ---- menu and misc UI text ----
msgTitle  BYTE "==============================================",0Dh,0Ah
          BYTE "   ASSEMBLY FILE INTEGRITY MONITOR  (FIM PRO)",0Dh,0Ah
          BYTE "   SHA-256 | HMAC seal | Recursive | Real-time",0Dh,0Ah
          BYTE "==============================================",0
msgOpt1   BYTE "  [1] Initialize Baseline (recursive scan)",0
msgOpt2   BYTE "  [2] Run Integrity Check",0
msgOpt3   BYTE "  [3] Real-Time Monitor",0
msgOpt4   BYTE "  [4] View Event History",0
msgOpt5   BYTE "  [5] Exit",0
msgPrompt BYTE "  Select an option: ",0
msgBye    BYTE "Goodbye - stay secure!",0

msgInitHdr   BYTE "--- Creating baseline from folder 'monitored' ---",0
msgCheckHdr  BYTE "--- Integrity check ---",0
msgMonHdr    BYTE "--- Real-time monitor ---",0
msgHistHdr   BYTE "--- Event history (most recent entries) ---",0
msgHashed    BYTE "[HASHED]  SHA-256 ",0
msgDots      BYTE "...",0
msgOverwrite BYTE "A baseline already exists. Overwrite it? (Y/N): ",0
msgCancelled BYTE "Cancelled. Existing baseline kept.",0
msgEmpty     BYTE "No readable files found in 'monitored'. Create the folder and add files.",0
msgFull      BYTE "[LIMIT]  Too many files, extra files ignored.",0
msgSealed    BYTE "Baseline saved and sealed (baseline.txt + baseline.sig).",0
msgSaveErr   BYTE "ERROR: could not write baseline files.",0
msgNoBase    BYTE "ERROR: baseline not found. Run option [1] first.",0
msgBroken    BYTE "[ALERT]  BASELINE TAMPERED! Seal does not match - check refused.",0
msgSumPass   BYTE "Summary -> Passed: ",0
msgSumTam    BYTE "  Tampered: ",0
msgSumMis    BYTE "  Missing: ",0
msgSumNew    BYTE "  New: ",0
msgAllOk     BYTE "All monitored files are intact.",0
msgWatching  BYTE "Baseline verified. Watching 'monitored' (all sub-folders). Press any key to stop...",0
msgStopped   BYTE "Monitoring stopped.",0
msgNoNotify  BYTE "ERROR: could not start change notification (does 'monitored' exist?).",0
msgNoHist    BYTE "No events have been logged yet.",0
msgWas       BYTE "      baseline: ",0
msgNow       BYTE "..  now: ",0
msgDots2     BYTE "..",0

; ---- SHA-256 constants (fractional parts of cube roots of first 64 primes) ----
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
; ---- SHA-256 initial hash values (square roots of first 8 primes) ----
shaIV DWORD 06A09E667h, 0BB67AE85h, 03C6EF372h, 0A54FF53Ah
      DWORD 0510E527Fh, 09B05688Ch, 01F83D9ABh, 05BE0CD19h

; ---- SHA-256 running state ----
shaBufLen DWORD 0               ; bytes currently in shaBlock (0..63)
shaTotLo  DWORD 0               ; total message length in bytes (64-bit)
shaTotHi  DWORD 0
shaBitLo  DWORD 0               ; total length in BITS (for the padding)
shaBitHi  DWORD 0

; ---- program state ----
scanMode    DWORD 0             ; 0 = build baseline, 1 = compare
verbose     DWORD 1             ; 1 = also print [PASS] lines
depth       DWORD 0             ; current recursion depth
baseCount   DWORD 0             ; entries in baseDB
hashFailed  DWORD 0
textLen     DWORD 0
logLen      DWORD 0
passCount   DWORD 0
tamperCount DWORD 0
missCount   DWORD 0
newCount    DWORD 0

.data?
shaBlock   BYTE 64 DUP(?)       ; the 64-byte block being filled
shaW       DWORD 64 DUP(?)      ; message schedule W[0..63]
shaH       DWORD 8 DUP(?)       ; chaining value H0..H7
shaV       DWORD 8 DUP(?)       ; working variables a..h
sv_a TEXTEQU <shaV[0]>
sv_b TEXTEQU <shaV[4]>
sv_c TEXTEQU <shaV[8]>
sv_d TEXTEQU <shaV[12]>
sv_e TEXTEQU <shaV[16]>
sv_f TEXTEQU <shaV[20]>
sv_g TEXTEQU <shaV[24]>
sv_h TEXTEQU <shaV[28]>
curDigest    BYTE 32 DUP(?)     ; digest of the file just hashed
innerDigest  BYTE 32 DUP(?)     ; HMAC inner hash
macDigest    BYTE 32 DUP(?)     ; HMAC result
padBlk       BYTE 64 DUP(?)     ; HMAC ipad / opad block
macHex       BYTE 72 DUP(?)
hexBuf       BYTE 72 DUP(?)
sigBuf       BYTE 128 DUP(?)
fileBuf      BYTE BUF_SIZE DUP(?)
baseText     BYTE BASE_TEXT_MAX DUP(?)
baseDB       BYTE MAX_FILES*ENTRY_SIZE DUP(?)
histBuf      BYTE HIST_MAX+8 DUP(?)

.code
; =====================================================================
; PART 2 - SHA-256 ENGINE
;
;   Sha256Init    : reset state
;   Sha256Update  : ESI = data, ECX = byte count  (can be called many times)
;   Sha256Final   : EDI = 32-byte output buffer
;   Internals     : Sha256PutByte (AL) and Sha256Transform (one 64-byte block)
; =====================================================================

; ---------------------------------------------------------------------
; Sha256Init - load the 8 initial hash values, clear counters
; ---------------------------------------------------------------------
Sha256Init PROC
    push eax
    push ecx
    push esi
    push edi
    mov  esi, OFFSET shaIV
    mov  edi, OFFSET shaH
    mov  ecx, 8
    rep  movsd                  ; copy 8 DWORDs IV -> H
    mov  shaBufLen, 0
    mov  shaTotLo, 0
    mov  shaTotHi, 0
    pop  edi
    pop  esi
    pop  ecx
    pop  eax
    ret
Sha256Init ENDP

; ---------------------------------------------------------------------
; Sha256PutByte - append AL to the block; run Transform when it fills up
; ---------------------------------------------------------------------
Sha256PutByte PROC
    push ebx
    mov  ebx, shaBufLen
    mov  shaBlock[ebx], al      ; store the byte
    inc  ebx
    mov  shaBufLen, ebx
    cmp  ebx, 64
    jb   pb_return
    call Sha256Transform        ; block full -> compress it
    mov  shaBufLen, 0
pb_return:
    pop  ebx
    ret
Sha256PutByte ENDP

; ---------------------------------------------------------------------
; Sha256Update - feed ECX bytes at ESI into the hash
; ---------------------------------------------------------------------
Sha256Update PROC
    push eax
    push ecx
    push esi
    add  shaTotLo, ecx          ; 64-bit running length
    adc  shaTotHi, 0
    jecxz su_done               ; nothing to do for length 0
su_loop:
    mov  al, [esi]
    call Sha256PutByte
    inc  esi
    dec  ecx
    jnz  su_loop
su_done:
    pop  esi
    pop  ecx
    pop  eax
    ret
Sha256Update ENDP

; ---------------------------------------------------------------------
; Sha256Transform - the SHA-256 compression function for ONE 64-byte block
; ---------------------------------------------------------------------
Sha256Transform PROC
    pushad

    ; ---- Step A: W[0..15] = block as 16 big-endian DWORDs ----
    mov  esi, OFFSET shaBlock
    mov  edi, OFFSET shaW
    mov  ecx, 16
tr_load:
    mov  eax, [esi]
    bswap eax                   ; SHA is big-endian, x86 is little-endian
    mov  [edi], eax
    add  esi, 4
    add  edi, 4
    loop tr_load

    ; ---- Step B: expand to W[16..63] ----
    ;   s0 = ror(W[i-15],7)  ^ ror(W[i-15],18) ^ (W[i-15] >> 3)
    ;   s1 = ror(W[i-2],17)  ^ ror(W[i-2],19)  ^ (W[i-2]  >> 10)
    ;   W[i] = W[i-16] + s0 + W[i-7] + s1
    mov  ebx, 16
tr_sched:
    mov  eax, shaW[ebx*4-60]    ; W[i-15]
    mov  ecx, eax
    mov  edx, eax
    ror  eax, 7
    ror  ecx, 18
    shr  edx, 3
    xor  eax, ecx
    xor  eax, edx               ; EAX = s0
    mov  esi, eax
    mov  eax, shaW[ebx*4-8]     ; W[i-2]
    mov  ecx, eax
    mov  edx, eax
    ror  eax, 17
    ror  ecx, 19
    shr  edx, 10
    xor  eax, ecx
    xor  eax, edx               ; EAX = s1
    add  eax, esi               ; + s0
    add  eax, shaW[ebx*4-64]    ; + W[i-16]
    add  eax, shaW[ebx*4-28]    ; + W[i-7]
    mov  shaW[ebx*4], eax
    inc  ebx
    cmp  ebx, 64
    jb   tr_sched

    ; ---- Step C: working variables a..h = current hash H0..H7 ----
    mov  esi, OFFSET shaH
    mov  edi, OFFSET shaV
    mov  ecx, 8
    rep  movsd

    ; ---- Step D: 64 rounds ----
    xor  ebx, ebx               ; EBX = round number i
tr_round:
    ; Sigma1(e) = ror(e,6) ^ ror(e,11) ^ ror(e,25)
    mov  eax, sv_e
    mov  ecx, eax
    mov  edx, eax
    ror  eax, 6
    ror  ecx, 11
    ror  edx, 25
    xor  eax, ecx
    xor  eax, edx
    add  eax, sv_h              ; h + Sigma1
    ; Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g)
    mov  ecx, sv_e
    and  ecx, sv_f
    mov  edx, sv_e
    not  edx
    and  edx, sv_g
    xor  ecx, edx
    add  eax, ecx               ; + Ch
    add  eax, K256[ebx*4]       ; + K[i]
    add  eax, shaW[ebx*4]       ; + W[i]
    mov  esi, eax               ; ESI = T1
    ; Sigma0(a) = ror(a,2) ^ ror(a,13) ^ ror(a,22)
    mov  eax, sv_a
    mov  ecx, eax
    mov  edx, eax
    ror  eax, 2
    ror  ecx, 13
    ror  edx, 22
    xor  eax, ecx
    xor  eax, edx
    ; Maj(a,b,c) = (a&b) ^ (a&c) ^ (b&c)
    mov  ecx, sv_a
    and  ecx, sv_b
    mov  edx, sv_a
    and  edx, sv_c
    xor  ecx, edx
    mov  edx, sv_b
    and  edx, sv_c
    xor  ecx, edx
    add  eax, ecx               ; EAX = T2 = Sigma0 + Maj
    ; shift the variables: h=g g=f f=e e=d+T1 d=c c=b b=a a=T1+T2
    mov  ecx, sv_g
    mov  sv_h, ecx
    mov  ecx, sv_f
    mov  sv_g, ecx
    mov  ecx, sv_e
    mov  sv_f, ecx
    mov  ecx, sv_d
    add  ecx, esi
    mov  sv_e, ecx
    mov  ecx, sv_c
    mov  sv_d, ecx
    mov  ecx, sv_b
    mov  sv_c, ecx
    mov  ecx, sv_a
    mov  sv_b, ecx
    add  eax, esi
    mov  sv_a, eax
    inc  ebx
    cmp  ebx, 64
    jb   tr_round

    ; ---- Step E: H[i] += working variable [i] ----
    xor  ecx, ecx
tr_add:
    mov  eax, shaV[ecx*4]
    add  shaH[ecx*4], eax
    inc  ecx
    cmp  ecx, 8
    jb   tr_add

    popad
    ret
Sha256Transform ENDP

; ---------------------------------------------------------------------
; Sha256Final - padding + last block(s); writes 32-byte digest at [EDI]
;   padding = 0x80, zeros until length = 56 (mod 64), 64-bit bit-length
; ---------------------------------------------------------------------
Sha256Final PROC
    pushad
    mov  eax, shaTotLo          ; bit length = byte length * 8
    mov  edx, shaTotHi
    shld edx, eax, 3            ; high part gets the 3 bits shifted out
    shl  eax, 3
    mov  shaBitLo, eax
    mov  shaBitHi, edx

    mov  al, 80h                ; mandatory '1' bit
    call Sha256PutByte
fin_pad:
    cmp  shaBufLen, 56
    je   fin_len
    xor  al, al
    call Sha256PutByte          ; zero padding (may roll into a new block)
    jmp  fin_pad
fin_len:
    mov  eax, shaBitHi
    bswap eax
    mov  DWORD PTR shaBlock[56], eax
    mov  eax, shaBitLo
    bswap eax
    mov  DWORD PTR shaBlock[60], eax
    call Sha256Transform        ; final block

    mov  esi, OFFSET shaH       ; output H0..H7 big-endian
    mov  ecx, 8
fin_out:
    mov  eax, [esi]
    bswap eax
    mov  [edi], eax
    add  esi, 4
    add  edi, 4
    loop fin_out
    popad
    ret
Sha256Final ENDP

; ---------------------------------------------------------------------
; XorPad64 - XOR all 64 bytes of padBlk with BL (helper for HMAC)
; ---------------------------------------------------------------------
XorPad64 PROC
    push ecx
    push esi
    mov  esi, OFFSET padBlk
    mov  ecx, 64
xp_loop:
    xor  [esi], bl
    inc  esi
    loop xp_loop
    pop  esi
    pop  ecx
    ret
XorPad64 ENDP

; ---------------------------------------------------------------------
; HmacSha256 - HMAC(key, msg) = H( (K^opad) || H( (K^ipad) || msg ) )
;   msgPtr/msgLen = message, outPtr = 32-byte result
; ---------------------------------------------------------------------
HmacSha256 PROC USES eax ebx ecx esi edi, msgPtr:PTR BYTE, msgLen:DWORD, outPtr:PTR BYTE
    cld
    mov  edi, OFFSET padBlk     ; K' = key padded with zeros to 64 bytes
    xor  eax, eax
    mov  ecx, 16
    rep  stosd
    mov  esi, OFFSET hmacKey
    mov  edi, OFFSET padBlk
    mov  ecx, LENGTHOF hmacKey - 1
    rep  movsb

    mov  bl, 36h                ; ipad
    call XorPad64
    call Sha256Init             ; ---- inner hash ----
    mov  esi, OFFSET padBlk
    mov  ecx, 64
    call Sha256Update
    mov  esi, msgPtr
    mov  ecx, msgLen
    call Sha256Update
    mov  edi, OFFSET innerDigest
    call Sha256Final

    mov  bl, 6Ah                ; 36h XOR 5Ch : turns ipad block into opad block
    call XorPad64
    call Sha256Init             ; ---- outer hash ----
    mov  esi, OFFSET padBlk
    mov  ecx, 64
    call Sha256Update
    mov  esi, OFFSET innerDigest
    mov  ecx, 32
    call Sha256Update
    mov  edi, outPtr
    call Sha256Final
    ret
HmacSha256 ENDP

; =====================================================================
; PART 3 - HELPERS
; =====================================================================

; ---------------------------------------------------------------------
; StrLen - ESI = string, returns EAX = length (ESI preserved)
; ---------------------------------------------------------------------
StrLen PROC
    xor  eax, eax
sl_loop:
    cmp  BYTE PTR [esi+eax], 0
    je   sl_done
    inc  eax
    jmp  sl_loop
sl_done:
    ret
StrLen ENDP

; ---------------------------------------------------------------------
; AppendStr - copy string ESI -> EDI (no terminator); EDI ends after it
; ---------------------------------------------------------------------
AppendStr PROC
as_loop:
    mov  al, [esi]
    test al, al
    jz   as_done
    mov  [edi], al
    inc  esi
    inc  edi
    jmp  as_loop
as_done:
    ret
AppendStr ENDP

; ---------------------------------------------------------------------
; DigestToHex - 32 bytes at ESI -> 64 uppercase hex chars at EDI
; ---------------------------------------------------------------------
DigestToHex PROC
    push eax
    push ecx
    push edx
    mov  ecx, 32
dh_loop:
    movzx eax, BYTE PTR [esi]
    mov  edx, eax
    shr  edx, 4                 ; high nibble
    mov  dl, hexTable[edx]
    mov  [edi], dl
    and  eax, 0Fh               ; low nibble
    mov  al, hexTable[eax]
    mov  [edi+1], al
    add  edi, 2
    inc  esi
    dec  ecx
    jnz  dh_loop
    pop  edx
    pop  ecx
    pop  eax
    ret
DigestToHex ENDP

; ---------------------------------------------------------------------
; HexVal - AL = ASCII hex digit -> AL = 0..15
; ---------------------------------------------------------------------
HexVal PROC
    cmp  al, '9'
    jbe  hv_digit
    cmp  al, 'F'
    jbe  hv_upper
    sub  al, 'a' - 10
    ret
hv_upper:
    sub  al, 'A' - 10
    ret
hv_digit:
    sub  al, '0'
    ret
HexVal ENDP

; ---------------------------------------------------------------------
; PutDec - EAX = value, ECX = digit count -> zero-padded decimal at [EDI]
;          EDI advances by ECX (EAX and ECX are destroyed)
; ---------------------------------------------------------------------
PutDec PROC
    push ebx
    push edx
    push esi
    add  edi, ecx               ; start at the END and fill backwards
    mov  esi, edi
    mov  ebx, 10
pd_loop:
    xor  edx, edx
    div  ebx                    ; EAX = EAX/10, EDX = remainder digit
    add  dl, '0'
    dec  edi
    mov  [edi], dl
    dec  ecx
    jnz  pd_loop
    mov  edi, esi
    pop  esi
    pop  edx
    pop  ebx
    ret
PutDec ENDP

; ---------------------------------------------------------------------
; PrintPadded - write the path, then pad with spaces to column 44
; ---------------------------------------------------------------------
PrintPadded PROC USES eax ecx edx esi, pathPtr:PTR BYTE
    mov  edx, pathPtr
    call WriteString
    mov  esi, pathPtr
    call StrLen
    mov  ecx, 44
    sub  ecx, eax
    jg   pp_pad
    mov  ecx, 1
pp_pad:
    mov  al, ' '
    call WriteChar
    dec  ecx
    jnz  pp_pad
    ret
PrintPadded ENDP

; ---------------------------------------------------------------------
; ReadWholeFile - read up to maxLen bytes of a file into bufPtr
;   returns EAX = bytes read, CF = 1 on failure
; ---------------------------------------------------------------------
ReadWholeFile PROC USES ebx, namePtr:PTR BYTE, bufPtr:PTR BYTE, maxLen:DWORD
    LOCAL hFile:DWORD, nRead:DWORD
    INVOKE CreateFileA, namePtr, ACC_READ, SHARE_RW, 0, MODE_OPEN, ATTR_NORMAL, 0
    cmp  eax, BAD_HANDLE
    je   rw_fail
    mov  hFile, eax
    mov  nRead, 0
    INVOKE ReadFile, hFile, bufPtr, maxLen, ADDR nRead, 0
    mov  ebx, eax               ; remember success flag
    INVOKE CloseHandle, hFile
    test ebx, ebx
    jz   rw_fail
    mov  eax, nRead
    clc
    ret
rw_fail:
    xor  eax, eax
    stc
    ret
ReadWholeFile ENDP

; ---------------------------------------------------------------------
; SaveFile - write dataLen bytes to a file (create / overwrite / append)
;   CF = 1 on failure
; ---------------------------------------------------------------------
SaveFile PROC USES ebx, namePtr:PTR BYTE, bufPtr:PTR BYTE, dataLen:DWORD, accMode:DWORD, dispMode:DWORD
    LOCAL hFile:DWORD, nWritten:DWORD
    INVOKE CreateFileA, namePtr, accMode, SHARE_R, 0, dispMode, ATTR_NORMAL, 0
    cmp  eax, BAD_HANDLE
    je   sf_fail
    mov  hFile, eax
    mov  nWritten, 0
    INVOKE WriteFile, hFile, bufPtr, dataLen, ADDR nWritten, 0
    mov  ebx, eax
    INVOKE CloseHandle, hFile
    test ebx, ebx
    jz   sf_fail
    clc
    ret
sf_fail:
    stc
    ret
SaveFile ENDP

; ---------------------------------------------------------------------
; LogEvent - append "YYYY-MM-DD HH:MM:SS | EVENT    | path" to the log
;   event text starts at column 22 (used to colour the history view)
; ---------------------------------------------------------------------
LogEvent PROC USES eax ecx edx esi edi, evPtr:PTR BYTE, pathPtr:PTR BYTE
    LOCAL sysTime[16]:BYTE      ; SYSTEMTIME: 8 WORDs
    LOCAL logLine[400]:BYTE

    INVOKE GetLocalTime, ADDR sysTime

    lea  edi, logLine
    movzx eax, WORD PTR sysTime[0]      ; wYear
    mov  ecx, 4
    call PutDec
    mov  BYTE PTR [edi], '-'
    inc  edi
    movzx eax, WORD PTR sysTime[2]      ; wMonth
    mov  ecx, 2
    call PutDec
    mov  BYTE PTR [edi], '-'
    inc  edi
    movzx eax, WORD PTR sysTime[6]      ; wDay
    mov  ecx, 2
    call PutDec
    mov  BYTE PTR [edi], ' '
    inc  edi
    movzx eax, WORD PTR sysTime[8]      ; wHour
    mov  ecx, 2
    call PutDec
    mov  BYTE PTR [edi], ':'
    inc  edi
    movzx eax, WORD PTR sysTime[10]     ; wMinute
    mov  ecx, 2
    call PutDec
    mov  BYTE PTR [edi], ':'
    inc  edi
    movzx eax, WORD PTR sysTime[12]     ; wSecond
    mov  ecx, 2
    call PutDec

    mov  esi, OFFSET sepStr             ; " | "
    call AppendStr
    mov  esi, evPtr
    call AppendStr
    mov  esi, OFFSET sepStr
    call AppendStr
    mov  esi, pathPtr
    call AppendStr
    mov  BYTE PTR [edi], 0Dh
    mov  BYTE PTR [edi+1], 0Ah
    add  edi, 2

    lea  eax, logLine
    sub  edi, eax
    mov  logLen, edi
    INVOKE SaveFile, ADDR logName, ADDR logLine, logLen, ACC_APPEND, MODE_ALWAYS
    ret
LogEvent ENDP

; ---------------------------------------------------------------------
; PrintStatus - path (padded) + coloured status message for stCode
; ---------------------------------------------------------------------
PrintStatus PROC USES eax ebx ecx edx esi edi, pathPtr:PTR BYTE, stCode:DWORD
    mov  eax, C_WHITE
    call SetTextColor
    INVOKE PrintPadded, pathPtr
    mov  ebx, stCode
    mov  eax, stColor[ebx*4]
    call SetTextColor
    mov  edx, stMsg[ebx*4]
    call WriteString
    mov  eax, C_WHITE
    call SetTextColor
    call Crlf
    ret
PrintStatus ENDP

; ---------------------------------------------------------------------
; ReportEvent - print the status AND write it to the history log
; ---------------------------------------------------------------------
ReportEvent PROC USES eax ebx ecx edx esi edi, pathPtr:PTR BYTE, stCode:DWORD
    INVOKE PrintStatus, pathPtr, stCode
    mov  ebx, stCode
    cmp  ebx, ST_PASS
    je   re_done
    mov  eax, stEvt[ebx*4]
    INVOKE LogEvent, eax, pathPtr
re_done:
    ret
ReportEvent ENDP

; =====================================================================
; PART 4 - BASELINE LOAD / VERIFY
; =====================================================================

; ---------------------------------------------------------------------
; ParseBaseline - turn baseText ("path | 64hex" lines) into baseDB entries
;   Each line: path = everything except the last 67 chars; the last 64
;   are the hash, the 3 before them are " | ". (Paths may contain spaces.)
; ---------------------------------------------------------------------
ParseBaseline PROC USES eax ebx ecx edx esi edi
    mov  baseCount, 0
    mov  esi, OFFSET baseText
ps_skip:                        ; skip blank space / line breaks
    mov  al, [esi]
    test al, al
    jz   ps_done
    cmp  al, 0Dh
    je   ps_adv
    cmp  al, 0Ah
    je   ps_adv
    jmp  ps_line
ps_adv:
    inc  esi
    jmp  ps_skip
ps_line:
    cmp  baseCount, MAX_FILES
    jae  ps_done
    mov  edx, esi               ; find the end of this line
ps_eol:
    mov  al, [edx]
    test al, al
    jz   ps_eolf
    cmp  al, 0Dh
    je   ps_eolf
    cmp  al, 0Ah
    je   ps_eolf
    inc  edx
    jmp  ps_eol
ps_eolf:
    mov  ecx, edx
    sub  ecx, esi               ; ECX = line length
    cmp  ecx, 68                ; need path(>=1) + 3 + 64
    jb   ps_done
    sub  ecx, 67                ; ECX = path length
    cmp  ecx, 259
    ja   ps_done
    cmp  BYTE PTR [esi+ecx], ' '
    jne  ps_done
    cmp  BYTE PTR [esi+ecx+1], '|'
    jne  ps_done

    mov  eax, baseCount         ; EBX = address of the new entry
    imul eax, ENTRY_SIZE
    add  eax, OFFSET baseDB
    mov  ebx, eax
    mov  edi, ebx
    rep  movsb                  ; copy the path (ECX bytes)
    mov  BYTE PTR [edi], 0
    add  esi, 3                 ; skip " | "

    lea  edi, [ebx + E_HASH]    ; 64 hex chars -> 32 bytes
    mov  ecx, 32
ps_hex:
    mov  al, [esi]
    call HexVal
    shl  al, 4
    mov  dl, al
    mov  al, [esi+1]
    call HexVal
    or   al, dl
    mov  [edi], al
    add  esi, 2
    inc  edi
    dec  ecx
    jnz  ps_hex

    mov  DWORD PTR [ebx + E_SEEN], 0
    mov  DWORD PTR [ebx + E_STATE], ST_PASS
    mov  DWORD PTR [ebx + E_ORIGIN], 0
    inc  baseCount
    jmp  ps_skip
ps_done:
    ret
ParseBaseline ENDP

; ---------------------------------------------------------------------
; LoadAndVerifyBaseline
;   1. read baseline.txt   2. read baseline.sig
;   3. recompute HMAC-SHA256(baseline.txt) and compare with the seal
;   4. only if they match, parse the baseline into memory
;   CF = 1 on any failure (message already printed)
; ---------------------------------------------------------------------
LoadAndVerifyBaseline PROC USES eax ecx esi edi
    INVOKE ReadWholeFile, ADDR baselineName, ADDR baseText, BASE_TEXT_MAX-1
    jc   lv_nobase
    mov  textLen, eax
    mov  BYTE PTR baseText[eax], 0

    INVOKE ReadWholeFile, ADDR sigName, ADDR sigBuf, 64
    jc   lv_broken              ; seal file missing = tampering
    cmp  eax, 64
    jne  lv_broken

    INVOKE HmacSha256, ADDR baseText, textLen, ADDR macDigest
    mov  esi, OFFSET macDigest
    mov  edi, OFFSET macHex
    call DigestToHex

    mov  esi, OFFSET macHex     ; compare recomputed vs stored seal
    mov  edi, OFFSET sigBuf
    mov  ecx, 64
    repe cmpsb
    jne  lv_broken

    call ParseBaseline
    clc
    ret

lv_nobase:
    mov  eax, C_RED
    call SetTextColor
    mov  edx, OFFSET msgNoBase
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    stc
    ret

lv_broken:
    mov  eax, C_RED
    call SetTextColor
    mov  edx, OFFSET msgBroken
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    INVOKE LogEvent, ADDR evAlert, ADDR baselineName
    stc
    ret
LoadAndVerifyBaseline ENDP

; =====================================================================
; PART 5 - HASHING A FILE, RECURSIVE SCAN, COMPARISON
; =====================================================================

; ---------------------------------------------------------------------
; HashFileSHA - SHA-256 of a file -> curDigest.   CF = 1 if unreadable
;   The file is opened with FILE_SHARE_READ|WRITE so files that another
;   program still has open can be read.
; ---------------------------------------------------------------------
HashFileSHA PROC USES ebx ecx edx esi edi, pathPtr:PTR BYTE
    LOCAL hFile:DWORD, nRead:DWORD
    INVOKE CreateFileA, pathPtr, ACC_READ, SHARE_RW, 0, MODE_OPEN, ATTR_NORMAL, 0
    cmp  eax, BAD_HANDLE
    je   hs_fail
    mov  hFile, eax
    call Sha256Init
hs_read:
    mov  nRead, 0
    INVOKE ReadFile, hFile, OFFSET fileBuf, BUF_SIZE, ADDR nRead, 0
    test eax, eax
    jz   hs_err
    cmp  nRead, 0               ; 0 bytes read = end of file
    je   hs_done
    mov  esi, OFFSET fileBuf
    mov  ecx, nRead
    call Sha256Update
    jmp  hs_read
hs_done:
    INVOKE CloseHandle, hFile
    mov  edi, OFFSET curDigest
    call Sha256Final
    clc
    ret
hs_err:
    INVOKE CloseHandle, hFile
hs_fail:
    stc
    ret
HashFileSHA ENDP

; ---------------------------------------------------------------------
; FindEntry - look a path up in baseDB. EAX = entry address or 0
; ---------------------------------------------------------------------
FindEntry PROC USES ebx ecx esi edi, pathPtr:PTR BYTE
    mov  ebx, OFFSET baseDB
    mov  ecx, baseCount
    test ecx, ecx
    jz   fe_none
fe_loop:
    mov  esi, pathPtr
    mov  edi, ebx
fe_cmp:
    mov  al, [esi]
    cmp  al, [edi]
    jne  fe_next
    test al, al
    jz   fe_found               ; both strings ended together = equal
    inc  esi
    inc  edi
    jmp  fe_cmp
fe_next:
    add  ebx, ENTRY_SIZE
    dec  ecx
    jnz  fe_loop
fe_none:
    xor  eax, eax
    ret
fe_found:
    mov  eax, ebx
    ret
FindEntry ENDP

; ---------------------------------------------------------------------
; ProcessFile - called once for every file the scanner finds
;   scanMode 0 : add the file to the baseline
;   scanMode 1 : compare it with the baseline and report CHANGES
;                (a state change is printed + logged; PASS is printed
;                 only when verbose = 1)
; ---------------------------------------------------------------------
ProcessFile PROC USES ebx ecx edx esi edi, pathPtr:PTR BYTE
    mov  hashFailed, 0
    INVOKE HashFileSHA, pathPtr
    jnc  pf_hashed
    mov  hashFailed, 1
pf_hashed:
    cmp  scanMode, 0
    je   pf_baseline

    ; ============ compare mode ============
    INVOKE FindEntry, pathPtr
    mov  ebx, eax               ; EBX = entry (0 if not in baseline)
    cmp  hashFailed, 0
    jne  pf_locked
    test ebx, ebx
    jz   pf_new

    mov  DWORD PTR [ebx + E_SEEN], 1
    mov  esi, OFFSET curDigest  ; compare 8 DWORDs = 32 bytes
    lea  edi, [ebx + E_HASH]
    mov  ecx, 8
    repe cmpsd
    jne  pf_diff
    mov  eax, ST_PASS           ; digest equal
    cmp  DWORD PTR [ebx + E_ORIGIN], 1
    jne  pf_state
    mov  eax, ST_NEW            ; equal, but file was discovered new earlier
    jmp  pf_state
pf_diff:
    mov  eax, ST_TAMPER
pf_state:                       ; EAX = state of the file right now
    cmp  eax, ST_PASS
    jne  pf_t1
    inc  passCount
    jmp  pf_tally_done
pf_t1:
    cmp  eax, ST_TAMPER
    jne  pf_t2
    inc  tamperCount
    jmp  pf_tally_done
pf_t2:
    inc  newCount
pf_tally_done:
    cmp  eax, [ebx + E_STATE]
    je   pf_same                ; no change since last time
    mov  [ebx + E_STATE], eax   ; remember the new state
    mov  edx, ST_RESTORED       ; leaving TAMPERED/MISSING for OK = RESTORED
    cmp  eax, ST_TAMPER
    jne  pf_rep
    mov  edx, ST_TAMPER
pf_rep:
    INVOKE ReportEvent, pathPtr, edx
    cmp  DWORD PTR [ebx + E_STATE], ST_TAMPER
    jne  pf_done
    ; small detail line: first 4 bytes of old and new digest
    mov  eax, C_WHITE
    call SetTextColor
    mov  edx, OFFSET msgWas
    call WriteString
    mov  eax, DWORD PTR [ebx + E_HASH]
    bswap eax
    call WriteHex
    mov  edx, OFFSET msgNow
    call WriteString
    mov  eax, DWORD PTR curDigest
    bswap eax
    call WriteHex
    mov  edx, OFFSET msgDots2
    call WriteString
    call Crlf
    jmp  pf_done

pf_same:                        ; unchanged: print only in verbose mode
    cmp  verbose, 0
    je   pf_done
    INVOKE PrintStatus, pathPtr, eax
    jmp  pf_done

pf_locked:                      ; exists but cannot be opened
    test ebx, ebx
    jz   pf_done
    mov  DWORD PTR [ebx + E_SEEN], 1    ; do not mistake it for MISSING
    cmp  verbose, 0
    je   pf_done
    INVOKE PrintStatus, pathPtr, ST_LOCKED
    jmp  pf_done

pf_new:                         ; file not in baseline
    inc  newCount
    INVOKE ReportEvent, pathPtr, ST_NEW
    cmp  baseCount, MAX_FILES
    jae  pf_done
    mov  eax, baseCount         ; remember it (in memory only) so that the
    imul eax, ENTRY_SIZE        ; alert is not repeated on every rescan
    add  eax, OFFSET baseDB
    mov  ebx, eax
    mov  edi, ebx
    mov  esi, pathPtr
    call AppendStr
    mov  BYTE PTR [edi], 0
    mov  esi, OFFSET curDigest
    lea  edi, [ebx + E_HASH]
    mov  ecx, 8
    rep  movsd
    mov  DWORD PTR [ebx + E_SEEN], 1
    mov  DWORD PTR [ebx + E_STATE], ST_NEW
    mov  DWORD PTR [ebx + E_ORIGIN], 1
    inc  baseCount
    jmp  pf_done

    ; ============ baseline-building mode ============
pf_baseline:
    cmp  hashFailed, 0
    jne  pf_blocked
    cmp  baseCount, MAX_FILES
    jae  pf_full
    mov  eax, baseCount
    imul eax, ENTRY_SIZE
    add  eax, OFFSET baseDB
    mov  ebx, eax
    mov  edi, ebx
    mov  esi, pathPtr
    call AppendStr              ; store the path
    mov  BYTE PTR [edi], 0
    mov  esi, OFFSET curDigest
    lea  edi, [ebx + E_HASH]
    mov  ecx, 8
    rep  movsd                  ; store the digest
    mov  DWORD PTR [ebx + E_SEEN], 0
    mov  DWORD PTR [ebx + E_STATE], ST_PASS
    mov  DWORD PTR [ebx + E_ORIGIN], 0
    inc  baseCount

    mov  eax, C_WHITE           ; show "path   [HASHED] first-16-hex..."
    call SetTextColor
    INVOKE PrintPadded, pathPtr
    mov  eax, C_GREEN
    call SetTextColor
    mov  edx, OFFSET msgHashed
    call WriteString
    mov  esi, OFFSET curDigest
    mov  edi, OFFSET hexBuf
    call DigestToHex
    mov  BYTE PTR hexBuf[16], 0
    mov  edx, OFFSET hexBuf
    call WriteString
    mov  edx, OFFSET msgDots
    call WriteString
    mov  eax, C_WHITE
    call SetTextColor
    call Crlf
    jmp  pf_done
pf_blocked:
    INVOKE PrintStatus, pathPtr, ST_LOCKED
    jmp  pf_done
pf_full:
    mov  eax, C_YELLOW
    call SetTextColor
    mov  edx, OFFSET msgFull
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
pf_done:
    ret
ProcessFile ENDP

; ---------------------------------------------------------------------
; ScanDir - RECURSIVE directory walk
;   For every entry in dirPtr:  "." and ".." are skipped,
;   sub-directories -> ScanDir calls itself,  files -> ProcessFile.
;   Each recursion level has its own stack frame (LOCAL variables), so
;   every level keeps its own search handle and buffers.
; ---------------------------------------------------------------------
ScanDir PROC USES ebx esi edi, dirPtr:PTR BYTE
    LOCAL hFind:DWORD
    LOCAL fd[320]:BYTE          ; WIN32_FIND_DATAA
    LOCAL fullPath[288]:BYTE

    cmp  depth, MAX_DEPTH       ; safety: do not recurse forever
    jae  sd_exit
    inc  depth

    lea  edi, fullPath          ; search pattern = dir + "\*"
    mov  esi, dirPtr
    call AppendStr
    mov  esi, OFFSET starStr
    call AppendStr
    mov  BYTE PTR [edi], 0

    INVOKE FindFirstFileA, ADDR fullPath, ADDR fd
    cmp  eax, BAD_HANDLE
    je   sd_leave               ; folder missing or empty
    mov  hFind, eax

sd_entry:
    lea  esi, fd                ; ESI -> cFileName
    add  esi, F_NAME
    cmp  BYTE PTR [esi], '.'    ; skip "." and ".."
    jne  sd_real
    cmp  BYTE PTR [esi+1], 0
    je   sd_advance
    cmp  BYTE PTR [esi+1], '.'
    jne  sd_real
    cmp  BYTE PTR [esi+2], 0
    je   sd_advance
sd_real:
    mov  eax, DWORD PTR fd[F_ATTR]
    test eax, ATTR_REPARSE      ; skip symlinks / junctions
    jnz  sd_advance

    mov  esi, dirPtr            ; path too long?  dir + "\" + name <= 259
    call StrLen
    mov  ebx, eax
    lea  esi, fd
    add  esi, F_NAME
    call StrLen
    add  eax, ebx
    inc  eax
    cmp  eax, 259
    ja   sd_advance

    lea  edi, fullPath          ; fullPath = dir + "\" + name
    mov  esi, dirPtr
    call AppendStr
    mov  BYTE PTR [edi], '\'
    inc  edi
    lea  esi, fd
    add  esi, F_NAME
    call AppendStr
    mov  BYTE PTR [edi], 0

    mov  eax, DWORD PTR fd[F_ATTR]
    test eax, ATTR_DIR
    jnz  sd_isdir
    INVOKE ProcessFile, ADDR fullPath       ; a file
    jmp  sd_advance
sd_isdir:
    INVOKE ScanDir, ADDR fullPath           ; a folder -> RECURSION

sd_advance:
    INVOKE FindNextFileA, hFind, ADDR fd
    test eax, eax
    jnz  sd_entry               ; more entries
    INVOKE FindClose, hFind
sd_leave:
    dec  depth
sd_exit:
    ret
ScanDir ENDP

; ---------------------------------------------------------------------
; ScanOnce - one full comparison pass over the tree:
;   clear "seen" flags, scan, then report every baseline entry that was
;   NOT seen as MISSING (only when its state changes)
; ---------------------------------------------------------------------
ScanOnce PROC USES eax ebx ecx
    mov  ebx, OFFSET baseDB
    mov  ecx, baseCount
    jecxz so_scan
so_clear:
    mov  DWORD PTR [ebx + E_SEEN], 0
    add  ebx, ENTRY_SIZE
    dec  ecx
    jnz  so_clear
so_scan:
    mov  depth, 0
    INVOKE ScanDir, ADDR rootDir

    mov  ebx, OFFSET baseDB
    mov  ecx, baseCount
    jecxz so_done
so_check:
    cmp  DWORD PTR [ebx + E_SEEN], 0
    jne  so_next
    inc  missCount
    cmp  DWORD PTR [ebx + E_STATE], ST_MISSING
    je   so_next                ; already reported
    mov  DWORD PTR [ebx + E_STATE], ST_MISSING
    INVOKE ReportEvent, ebx, ST_MISSING
so_next:
    add  ebx, ENTRY_SIZE
    dec  ecx
    jnz  so_check
so_done:
    ret
ScanOnce ENDP

; =====================================================================
; PART 6 - MENU ACTIONS
; =====================================================================

; ---------------------------------------------------------------------
; InitBaseline - scan, write baseline.txt, write baseline.sig (HMAC)
; ---------------------------------------------------------------------
InitBaseline PROC USES eax ebx ecx edx esi edi
    call Crlf
    INVOKE ReadWholeFile, ADDR baselineName, ADDR sigBuf, 1   ; exists?
    jc   ib_go
    mov  eax, C_YELLOW          ; protect against accidental overwrite
    call SetTextColor
    mov  edx, OFFSET msgOverwrite
    call WriteString
    call ReadChar
    call WriteChar
    call Crlf
    mov  ebx, eax
    mov  eax, C_WHITE
    call SetTextColor
    or   bl, 20h                ; to lower case
    cmp  bl, 'y'
    je   ib_go
    mov  edx, OFFSET msgCancelled
    call WriteString
    call Crlf
    jmp  ib_exit

ib_go:
    mov  eax, C_WHITE
    call SetTextColor
    mov  edx, OFFSET msgInitHdr
    call WriteString
    call Crlf
    call Crlf
    mov  baseCount, 0
    mov  scanMode, 0
    mov  verbose, 1
    mov  depth, 0
    INVOKE ScanDir, ADDR rootDir

    cmp  baseCount, 0
    jne  ib_build
    mov  eax, C_YELLOW
    call SetTextColor
    mov  edx, OFFSET msgEmpty
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    jmp  ib_exit

ib_build:                       ; build the text "path | HASH" line by line
    mov  edi, OFFSET baseText
    mov  ebx, OFFSET baseDB
    mov  ecx, baseCount
ib_line:
    mov  esi, ebx
    call AppendStr              ; path
    mov  esi, OFFSET sepStr
    call AppendStr              ; " | "
    lea  esi, [ebx + E_HASH]
    call DigestToHex            ; 64 hex characters
    mov  BYTE PTR [edi], 0Dh
    mov  BYTE PTR [edi+1], 0Ah
    add  edi, 2
    add  ebx, ENTRY_SIZE
    dec  ecx
    jnz  ib_line
    mov  eax, edi
    sub  eax, OFFSET baseText
    mov  textLen, eax

    INVOKE SaveFile, ADDR baselineName, ADDR baseText, textLen, ACC_WRITE, MODE_CREATE
    jc   ib_err
    INVOKE HmacSha256, ADDR baseText, textLen, ADDR macDigest   ; the seal
    mov  esi, OFFSET macDigest
    mov  edi, OFFSET macHex
    call DigestToHex
    INVOKE SaveFile, ADDR sigName, ADDR macHex, 64, ACC_WRITE, MODE_CREATE
    jc   ib_err

    INVOKE LogEvent, ADDR evBaseline, ADDR rootDir
    call Crlf
    mov  eax, C_CYAN
    call SetTextColor
    mov  edx, OFFSET msgSealed
    call WriteString
    call Crlf
    jmp  ib_reset
ib_err:
    mov  eax, C_RED
    call SetTextColor
    mov  edx, OFFSET msgSaveErr
    call WriteString
    call Crlf
ib_reset:
    mov  eax, C_WHITE
    call SetTextColor
ib_exit:
    ret
InitBaseline ENDP

; ---------------------------------------------------------------------
; RunCheck - verify seal, scan tree, print PASS/TAMPERED/MISSING/NEW
; ---------------------------------------------------------------------
RunCheck PROC USES eax edx
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    mov  edx, OFFSET msgCheckHdr
    call WriteString
    call Crlf
    call Crlf
    call LoadAndVerifyBaseline
    jc   rc_exit
    mov  scanMode, 1
    mov  verbose, 1
    mov  passCount, 0
    mov  tamperCount, 0
    mov  missCount, 0
    mov  newCount, 0
    call ScanOnce

    call Crlf
    mov  edx, OFFSET msgSumPass
    call WriteString
    mov  eax, passCount
    call WriteDec
    mov  edx, OFFSET msgSumTam
    call WriteString
    mov  eax, tamperCount
    call WriteDec
    mov  edx, OFFSET msgSumMis
    call WriteString
    mov  eax, missCount
    call WriteDec
    mov  edx, OFFSET msgSumNew
    call WriteString
    mov  eax, newCount
    call WriteDec
    call Crlf
    mov  eax, tamperCount
    or   eax, missCount
    or   eax, newCount
    jnz  rc_exit
    mov  eax, C_GREEN
    call SetTextColor
    mov  edx, OFFSET msgAllOk
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    INVOKE LogEvent, ADDR evVerified, ADDR rootDir
rc_exit:
    ret
RunCheck ENDP

; ---------------------------------------------------------------------
; RealTimeMonitor - event driven watching
;   FindFirstChangeNotification gives a handle that becomes "signalled"
;   whenever something inside 'monitored' (or below) changes.
;   WaitForSingleObject waits on it (400 ms slices, so we can also poll
;   the keyboard). On a signal we rescan and report only the CHANGES.
; ---------------------------------------------------------------------
RealTimeMonitor PROC USES eax edx
    LOCAL hNotify:DWORD
    call Crlf
    mov  eax, C_CYAN
    call SetTextColor
    mov  edx, OFFSET msgMonHdr
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    call Crlf
    call LoadAndVerifyBaseline
    jc   rm_exit

    mov  scanMode, 1            ; initial full check (prints everything)
    mov  verbose, 1
    mov  passCount, 0
    mov  tamperCount, 0
    mov  missCount, 0
    mov  newCount, 0
    call ScanOnce

    INVOKE FindFirstChangeNotificationA, OFFSET rootDir, 1, NOTIFY_FILTER
    cmp  eax, BAD_HANDLE
    je   rm_nohandle
    mov  hNotify, eax

    call Crlf
    mov  eax, C_CYAN
    call SetTextColor
    mov  edx, OFFSET msgWatching
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    INVOKE LogEvent, ADDR evWatch, ADDR rootDir
    mov  verbose, 0             ; from now on: print changes only

rm_loop:
    INVOKE WaitForSingleObject, hNotify, 400
    test eax, eax               ; 0 = WAIT_OBJECT_0 = something changed
    jz   rm_changed
    cmp  eax, 102h              ; WAIT_TIMEOUT -> just check the keyboard
    je   rm_key
    jmp  rm_stop                ; WAIT_FAILED -> leave
rm_changed:
    INVOKE Sleep, 300                       ; let the writer finish saving
    INVOKE FindNextChangeNotification, hNotify  ; re-arm before scanning,
                                             ; so changes mid-scan aren't lost
    call ScanOnce
rm_key:
    call ReadKey                ; ZF = 1 when no key is waiting
    jz   rm_loop

rm_stop:
    INVOKE FindCloseChangeNotification, hNotify
    INVOKE LogEvent, ADDR evWatch, ADDR rootDir
    call Crlf
    mov  edx, OFFSET msgStopped
    call WriteString
    call Crlf
    jmp  rm_exit
rm_nohandle:
    mov  eax, C_RED
    call SetTextColor
    mov  edx, OFFSET msgNoNotify
    call WriteString
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
rm_exit:
    ret
RealTimeMonitor ENDP

; ---------------------------------------------------------------------
; EventColor - DL = first letter of the event name -> EAX = colour
; ---------------------------------------------------------------------
EventColor PROC
    mov  eax, C_RED
    cmp  dl, 'T'
    je   ec_ret
    cmp  dl, 'A'
    je   ec_ret
    mov  eax, C_YELLOW
    cmp  dl, 'M'
    je   ec_ret
    cmp  dl, 'N'
    je   ec_ret
    cmp  dl, 'L'
    je   ec_ret
    mov  eax, C_CYAN
    cmp  dl, 'B'
    je   ec_ret
    cmp  dl, 'W'
    je   ec_ret
    mov  eax, C_GREEN
    cmp  dl, 'V'
    je   ec_ret
    cmp  dl, 'R'
    je   ec_ret
    mov  eax, C_WHITE
ec_ret:
    ret
EventColor ENDP

; ---------------------------------------------------------------------
; ShowHistory - print the tail of fim_history.log, one colour per event
; ---------------------------------------------------------------------
ShowHistory PROC USES eax ebx ecx edx esi edi
    LOCAL hFile:DWORD, nRead:DWORD
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    mov  edx, OFFSET msgHistHdr
    call WriteString
    call Crlf
    call Crlf

    INVOKE CreateFileA, OFFSET logName, ACC_READ, SHARE_RW, 0, MODE_OPEN, ATTR_NORMAL, 0
    cmp  eax, BAD_HANDLE
    je   sh_none
    mov  hFile, eax

    xor  ebx, ebx               ; EBX = 1 if we started mid-file
    INVOKE GetFileSize, hFile, 0
    cmp  eax, HIST_MAX
    jbe  sh_read
    sub  eax, HIST_MAX          ; too big: jump to the last HIST_MAX bytes
    INVOKE SetFilePointer, hFile, eax, 0, 0     ; 0 = FILE_BEGIN
    mov  ebx, 1
sh_read:
    mov  nRead, 0
    INVOKE ReadFile, hFile, OFFSET histBuf, HIST_MAX, ADDR nRead, 0
    INVOKE CloseHandle, hFile
    mov  eax, nRead
    mov  BYTE PTR histBuf[eax], 0
    mov  esi, OFFSET histBuf
    test ebx, ebx
    jz   sh_next
sh_skip1:                       ; drop the partial first line
    mov  al, [esi]
    test al, al
    jz   sh_end
    inc  esi
    cmp  al, 0Ah
    jne  sh_skip1

sh_next:
    mov  al, [esi]
    test al, al
    jz   sh_end
    cmp  al, 0Dh
    je   sh_adv
    cmp  al, 0Ah
    je   sh_adv
    mov  edi, esi               ; find the end of this line
sh_eol:
    mov  al, [edi]
    test al, al
    jz   sh_have
    cmp  al, 0Dh
    je   sh_have
    cmp  al, 0Ah
    je   sh_have
    inc  edi
    jmp  sh_eol
sh_have:
    mov  bl, [edi]              ; save the terminator, cut the line
    mov  BYTE PTR [edi], 0
    mov  eax, C_WHITE
    mov  ecx, edi
    sub  ecx, esi
    cmp  ecx, 23
    jb   sh_print
    movzx edx, BYTE PTR [esi+22]        ; first letter of the event name
    call EventColor
sh_print:
    call SetTextColor
    mov  edx, esi
    call WriteString
    call Crlf
    mov  [edi], bl              ; restore terminator
    mov  esi, edi
    jmp  sh_next
sh_adv:
    inc  esi
    jmp  sh_next
sh_end:
    mov  eax, C_WHITE
    call SetTextColor
    jmp  sh_exit
sh_none:
    mov  edx, OFFSET msgNoHist
    call WriteString
    call Crlf
sh_exit:
    ret
ShowHistory ENDP

; ---------------------------------------------------------------------
; ShowMenu
; ---------------------------------------------------------------------
ShowMenu PROC USES eax edx
    mov  eax, C_CYAN
    call SetTextColor
    mov  edx, OFFSET msgTitle
    call WriteString
    call Crlf
    call Crlf
    mov  eax, C_WHITE
    call SetTextColor
    mov  edx, OFFSET msgOpt1
    call WriteString
    call Crlf
    mov  edx, OFFSET msgOpt2
    call WriteString
    call Crlf
    mov  edx, OFFSET msgOpt3
    call WriteString
    call Crlf
    mov  edx, OFFSET msgOpt4
    call WriteString
    call Crlf
    mov  edx, OFFSET msgOpt5
    call WriteString
    call Crlf
    call Crlf
    mov  edx, OFFSET msgPrompt
    call WriteString
    ret
ShowMenu ENDP

; =====================================================================
; PART 7 - MAIN
; =====================================================================
main PROC
menu_loop:
    call Clrscr
    call ShowMenu
    call ReadChar               ; AL = key (no echo)
    cmp  al, '1'
    je   do_init
    cmp  al, '2'
    je   do_check
    cmp  al, '3'
    je   do_monitor
    cmp  al, '4'
    je   do_hist
    cmp  al, '5'
    je   do_exit
    jmp  menu_loop

do_init:
    call InitBaseline
    jmp  do_pause
do_check:
    call RunCheck
    jmp  do_pause
do_monitor:
    call RealTimeMonitor
    jmp  do_pause
do_hist:
    call ShowHistory
do_pause:
    call Crlf
    call WaitMsg
    jmp  menu_loop

do_exit:
    call Crlf
    mov  edx, OFFSET msgBye
    call WriteString
    call Crlf
    exit
main ENDP

END main
