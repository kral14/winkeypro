; ==============================================================================
; WinKey Pro -- Resmi Windows Qurasdiricisi (NSIS One-Click Setup)
; ==============================================================================

Unicode True
SetCompressor /SOLID lzma

!define PRODUCT_NAME "WinKey Pro"
!define PRODUCT_VERSION "0.1.0"
!define PRODUCT_PUBLISHER "WinKey Pro Security"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\winkey_desktop.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinKeyPro"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; UAC Administrator icazesi mecburidir
RequestExecutionLevel admin

; Cixis fayli ve susmaya gore qurasdirma yeri
OutFile "..\dist\WinKeySetup.exe"
InstallDir "$PROGRAMFILES64\WinKey Pro"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

; ==============================================================================
; Modern UI 2 Tenzimlemeleri
; ==============================================================================
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

; Pencere Basligi ve Mehsul Adi
Name "${PRODUCT_NAME}"
Caption "${PRODUCT_NAME} Setup"
BrandingText "WinKey Pro · Tehlukesizlik ve Uzaqdan Idareetme"

Function .onInit
    SetRegView 64
FunctionEnd

Function un.onInit
    SetRegView 64
FunctionEnd

!define MUI_ABORTWARNING
!define MUI_ICON "..\apps\desktop_tauri\src-tauri\icons\icon.ico"
!define MUI_UNICON "..\apps\desktop_tauri\src-tauri\icons\icon.ico"

; 1. Xos Geldiniz Sehifesi
!define MUI_WELCOMEPAGE_TITLE "WinKey Pro Qurasdiricisina Xos Gelmisiniz"
!define MUI_WELCOMEPAGE_TEXT "Bu sehrbaz WinKey Pro (v0.1.0) proqramini ve onun arxa plan tehlukesizlik xidmetini komputerinize qurasdiracaq.$\r$\n$\r$\nQurasdirma zamani sistem xidmeti avtomatik tenzimlenecek, qorunan tehlukesizlik icazeleri tetbiq olunacaq ve masaustu idareetme merkezi basladilacaq.$\r$\n$\r$\nDavam etmek ucun 'Qurasdir' duymesini sixin."
!insertmacro MUI_PAGE_WELCOME

; 2. Qurasdirilma Prosesi Sehifesi
!define MUI_PAGE_HEADER_TEXT "WinKey Pro Qurasdirilir"
!define MUI_PAGE_HEADER_SUBTEXT "Fayllar ve sistem xidmeti tenzimlenir..."
!define MUI_INSTFILESPAGE_PROGRESSBAR "smooth"
!insertmacro MUI_PAGE_INSTFILES

; 3. Tamamlanma Sehifesi
!define MUI_FINISHPAGE_TITLE "Qurasdirma Ugurla Tamamlandi"
!define MUI_FINISHPAGE_TEXT "WinKey Pro ugurla qurasdirildi ve arxa plan tehlukesizlik xidmeti aktivlesdirildi.$\r$\n$\r$\nProqramda komputerinizin adi, tehlukesiz DPAPI PIN sahesi ve mobil telefonunuzu qosmaq ucun QR kod derhal acilacaq."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchApp"
!define MUI_FINISHPAGE_RUN_TEXT "WinKey Pro Idareetme Merkezini Ac"
!insertmacro MUI_PAGE_FINISH

Function LaunchApp
    ExecShell "" "$INSTDIR\winkey_desktop.exe"
FunctionEnd

; Uninstaller sehifeleri
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; Standart basliqlarin ve Name placeholder-in temizlenmesi
LangString ^Name ${LANG_ENGLISH} "WinKey Pro"
LangString ^NameDA ${LANG_ENGLISH} "WinKey Pro"
LangString MUI_TEXT_INSTALLING_TITLE ${LANG_ENGLISH} "Qurasdirilir"
LangString MUI_TEXT_INSTALLING_SUBTITLE ${LANG_ENGLISH} "WinKey Pro komputerinize qurasdirilarken zehmet olmasa gozleyin."

; ==============================================================================
; Esas Qurasdirma Bolmesi
; ==============================================================================
Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    SetOverwrite on

    DetailPrint "Komponentler cixarilir..."
    File "..\apps\desktop_tauri\src-tauri\target\release\winkey_desktop.exe"
    File "..\apps\winkey_service\target\release\winkey_service.exe"
    File "..\apps\winkey_service\target\release\winkey_helper.exe"
    File "..\deploy\pre_signed_slot_a\manifest.json"
    File "..\deploy\pre_signed_slot_a\manifest.sig"
    File "..\scripts\service_installer.ps1"
    File "..\scripts\service_uninstaller.ps1"
    File "..\TELIMAT.md"
    File "..\deploy\migrations\001_initial_schema.sql"
    File "..\deploy\keys\prod_release_ed25519_pub.hex"

    ; Tehlukesiz ProgramData ve Slot A/B muhitinin hazirlanmasi
    DetailPrint "Tehlukesizlik icazeleri ve sistem xidmeti konfiqurasiya edilir..."
    
    ; service_installer.ps1 vasitesile tam tehlukesiz qurasdirma icra edilir (konsol penceresi gizledilir)
    nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$INSTDIR\service_installer.ps1" -SourceDir "$INSTDIR" -InstallDir "$INSTDIR" -Repair'
    Pop $0
    ${If} $0 != 0
        DetailPrint "XETA: Windows xidmeti qurasdirilmadi. Exit code: $0"
        MessageBox MB_ICONSTOP|MB_OK "WinKey xidmeti qurasdirilmadi (kod: $0). Qurasdirma tamamlanmadi. Detallar bolmesindeki xetani gonderin." /SD IDOK
        SetErrorLevel 1
        Abort
    ${Else}
        DetailPrint "Sistem xidmeti ve tehlukesizlik slotlari ugurla hazirlandi."
    ${EndIf}

    ; Default Gateway konfiqurasiyasinin yaradilmasi (eger movcud deyilse)
    IfFileExists "C:\ProgramData\WinKey\config.json" skip_config 0
        CreateDirectory "C:\ProgramData\WinKey"
        FileOpen $1 "C:\ProgramData\WinKey\config.json" w
        FileWrite $1 '{"gateway_origin":"http://127.0.0.1:8788","pc_name":""}'
        FileClose $1
    skip_config:

    ; Qisayollarin yaradilmasi
    DetailPrint "Start Menyusu ve Is Masasi qisayollari yaradilir..."
    CreateDirectory "$SMPROGRAMS\WinKey Pro"
    CreateShortcut "$SMPROGRAMS\WinKey Pro\WinKey Pro.lnk" "$INSTDIR\winkey_desktop.exe" "" "$INSTDIR\winkey_desktop.exe" 0
    CreateShortcut "$SMPROGRAMS\WinKey Pro\WinKey Pro Qaldir (Uninstall).lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
    CreateShortcut "$DESKTOP\WinKey Pro.lnk" "$INSTDIR\winkey_desktop.exe" "" "$INSTDIR\winkey_desktop.exe" 0

    ; Windows Registry (Apps & Features ucun qeydiyyat)
    DetailPrint "Windows Qurasdirilmis Proqramlar bazasinda qeydiyyat aparilir..."
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\winkey_desktop.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "WinKey Pro"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\winkey_desktop.exe,0"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoModify" 1
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoRepair" 1

    ; Istifadeci her defe Windows-a daxil olanda tray rejiminde ise dussun
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "WinKeyPro" '"$INSTDIR\winkey_desktop.exe" --minimized'

    ; Uninstaller binari generasiya edilir
    WriteUninstaller "$INSTDIR\uninstall.exe"

    DetailPrint "Qurasdirma muveffeqiyyetle basa catdi."
SectionEnd

; ==============================================================================
; Silinme Bolmesi (Uninstaller)
; ==============================================================================
Section "Uninstall"
    DetailPrint "WinKey Pro arxa plan xidmeti dayandirilir ve silinir..."
    nsExec::Exec 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& { & \"$INSTDIR\service_uninstaller.ps1\" -Silent }"'
    Pop $0

    ; Qisayollari sil
    Delete "$DESKTOP\WinKey Pro.lnk"
    Delete "$SMPROGRAMS\WinKey Pro\WinKey Pro.lnk"
    Delete "$SMPROGRAMS\WinKey Pro\WinKey Pro Qaldir (Uninstall).lnk"
    RMDir "$SMPROGRAMS\WinKey Pro"

    ; Registry qeydlerini temizle
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "WinKeyPro"

    ; Qurasdirilmis fayllari sil
    Delete "$INSTDIR\winkey_desktop.exe"
    Delete "$INSTDIR\winkey_service.exe"
    Delete "$INSTDIR\winkey_helper.exe"
    Delete "$INSTDIR\manifest.json"
    Delete "$INSTDIR\manifest.sig"
    Delete "$INSTDIR\service_installer.ps1"
    Delete "$INSTDIR\service_uninstaller.ps1"
    Delete "$INSTDIR\TELIMAT.md"
    Delete "$INSTDIR\001_initial_schema.sql"
    Delete "$INSTDIR\prod_release_ed25519_pub.hex"
    Delete "$INSTDIR\uninstall.exe"

    RMDir "$INSTDIR"

    SetAutoClose true
SectionEnd
