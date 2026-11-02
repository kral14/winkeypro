; ==============================================================================
; WinKey Pro -- Rəsmi Windows Quraşdırıcısı (NSIS One-Click Setup)
; ==============================================================================

Unicode True
SetCompressor /SOLID lzma

!define PRODUCT_NAME "WinKey Pro"
!ifndef PRODUCT_VERSION
!define PRODUCT_VERSION "0.1.0"
!endif
!define PRODUCT_PUBLISHER "WinKey Pro Security"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\winkey_desktop.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\WinKeyPro"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; UAC Administrator icazəsi məcburidir
RequestExecutionLevel admin

; Çıxış faylı və susmaya görə quraşdırma yeri
!ifndef OUTPUT_FILE
!define OUTPUT_FILE "..\dist\WinKeySetup.exe"
!endif
!ifndef MANIFEST_DIR
!define MANIFEST_DIR "..\deploy\pre_signed_slot_a"
!endif
OutFile "${OUTPUT_FILE}"
InstallDir "$PROGRAMFILES64\WinKey Pro"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

; ==============================================================================
; Modern UI 2 Tənzimləmələri
; ==============================================================================
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "nsDialogs.nsh"
Var DesktopShortcutSelected
Var DesktopShortcutCheckbox

; Pəncərə Başlığı və Məhsul Adı
Name "${PRODUCT_NAME}"
Caption "${PRODUCT_NAME} Setup"
BrandingText "WinKey Pro · Təhlükəsizlik və Uzaqdan İdarəetmə"

Function .onInit
    SetRegView 64
    StrCpy $DesktopShortcutSelected ${BST_CHECKED}
FunctionEnd

Function un.onInit
    SetRegView 64
FunctionEnd

!define MUI_ABORTWARNING
!define MUI_ICON "..\apps\desktop_tauri\src-tauri\icons\icon.ico"
!define MUI_UNICON "..\apps\desktop_tauri\src-tauri\icons\icon.ico"

; 1. Xoş Gəlmisiniz Səhifəsi
!define MUI_WELCOMEPAGE_TITLE "WinKey Pro Quraşdırıcısına Xoş Gəlmisiniz"
!define MUI_WELCOMEPAGE_TEXT "Bu sehrbaz WinKey Pro (v${PRODUCT_VERSION}) proqramını və onun arxa plan təhlükəsizlik xidmətini kompüterinizə quraşdıracaq.$\r$\n$\r$\nQuraşdırma zamanı sistem xidməti avtomatik tənzimlənəcək, qorunan təhlükəsizlik icazələri tətbiq olunacaq və masaüstü idarəetmə mərkəzi başladılacaq.$\r$\n$\r$\nDavam etmək üçün 'Quraşdır' düyməsini sıxın."
!insertmacro MUI_PAGE_WELCOME

Page custom ShortcutOptionsPage ShortcutOptionsLeave

Function ShortcutOptionsPage
    !insertmacro MUI_HEADER_TEXT "Qısayol seçimi" "Masaüstündə WinKey Pro qısayolu yaradılsın?"
    nsDialogs::Create 1018
    Pop $0
    ${If} $0 == error
        Abort
    ${EndIf}
    ${NSD_CreateCheckbox} 0 20u 100% 24u "Masaüstündə WinKey Pro qısayolu yarat"
    Pop $DesktopShortcutCheckbox
    ${NSD_SetState} $DesktopShortcutCheckbox $DesktopShortcutSelected
    nsDialogs::Show
FunctionEnd

Function ShortcutOptionsLeave
    ${NSD_GetState} $DesktopShortcutCheckbox $DesktopShortcutSelected
FunctionEnd

; 2. Quraşdırılma Prosesi Səhifəsi
!define MUI_PAGE_HEADER_TEXT "WinKey Pro Quraşdırılır"
!define MUI_PAGE_HEADER_SUBTEXT "Fayllar və sistem xidməti tənzimlənir..."
!define MUI_INSTFILESPAGE_PROGRESSBAR "smooth"
!insertmacro MUI_PAGE_INSTFILES

; 3. Tamamlanma Səhifəsi
!define MUI_FINISHPAGE_TITLE "Quraşdırma Uğurla Tamamlandı"
!define MUI_FINISHPAGE_TEXT "WinKey Pro uğurla quraşdırıldı və arxa plan təhlükəsizlik xidməti aktivləşdirildi.$\r$\n$\r$\nProqramda kompüterinizin adı, təhlükəsiz DPAPI PIN sahəsi və mobil telefonunuzu qoşmaq üçün QR kod dərhal açılacaq."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchApp"
!define MUI_FINISHPAGE_RUN_TEXT "WinKey Pro İdarəetmə Mərkəzini Aç"
!insertmacro MUI_PAGE_FINISH

Function LaunchApp
    InitPluginsDir
    File /oname=$PLUGINSDIR\launch_desktop_user.ps1 "..\scripts\launch_desktop_user.ps1"
    nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "$PLUGINSDIR\launch_desktop_user.ps1" -Executable "$INSTDIR\winkey_desktop.exe" -UnicodeOutput'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONEXCLAMATION|MB_OK "WinKey avtomatik açılmadı. Setup-ı bağlayın və Start menyusundan WinKey Pro proqramını açın." /SD IDOK
    ${EndIf}
FunctionEnd

; Uninstaller səhifələri
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; Standart başlıqların, Şriftin və Name placeholder-in tənzimlənməsi
LangString ^Font ${LANG_ENGLISH} "Segoe UI"
LangString ^FontSize ${LANG_ENGLISH} "9"
LangString ^Name ${LANG_ENGLISH} "WinKey Pro"
LangString ^NameDA ${LANG_ENGLISH} "WinKey Pro"

; ==============================================================================
; Əsas Quraşdırma Bölməsi
; ==============================================================================
Section "MainSection" SEC01
    ; Stop the installed service BEFORE extracting executable files.
    InitPluginsDir
    File /oname=$PLUGINSDIR\prepare_upgrade.ps1 "..\scripts\prepare_upgrade.ps1"
    DetailPrint "Mövcud WinKey xidməti və prosesləri dayandırılır..."
    nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$PLUGINSDIR\prepare_upgrade.ps1" -InstallDir "$INSTDIR" -UnicodeOutput'
    Pop $0
    ${If} $0 != 0
        MessageBox MB_ICONSTOP|MB_OK "WinKey xidməti dayandırılmadı. Fayllar dəyişdirilmədi. Detallar bölməsini yoxlayın." /SD IDOK
        SetErrorLevel 1
        Abort
    ${EndIf}
    SetOutPath "$INSTDIR"
    SetOverwrite on

    DetailPrint "Komponentlər çıxarılır..."
    File "..\apps\desktop_tauri\src-tauri\target\release\winkey_desktop.exe"
    File "..\apps\desktop_tauri\src-tauri\target\release\WebView2Loader.dll"
    File "..\apps\winkey_service\target\release\winkey_service.exe"
    File "..\apps\winkey_service\target\release\winkey_helper.exe"
    SetOutPath "$INSTDIR\helper_runtime"
    File /r "..\apps\winkey_service\target\release\helper_runtime\*.*"
    SetOutPath "$INSTDIR"
    File "${MANIFEST_DIR}\manifest.json"
    File "${MANIFEST_DIR}\manifest.sig"
    File "..\scripts\service_installer.ps1"
    File "..\scripts\service_uninstaller.ps1"
    File /oname=TELIMAT.md "..\docs\USER_GUIDE.md"
    File "..\deploy\migrations\001_initial_schema.sql"
    File "..\deploy\keys\prod_release_ed25519_pub.hex"

    ; Təhlükəsiz ProgramData və Slot A/B mühitinin hazırlanması
    DetailPrint "Təhlükəsizlik icazələri və sistem xidməti konfiqurasiya edilir..."

    ; service_installer.ps1 vasitəsilə tam təhlükəsiz quraşdırma icra edilir (konsol pəncərəsi gizlədilir)
    nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$INSTDIR\service_installer.ps1" -SourceDir "$INSTDIR" -InstallDir "$INSTDIR" -Repair -UnicodeOutput'
    Pop $0
    ${If} $0 != 0
        DetailPrint "XƏTA: Windows xidməti quraşdırılmadı. Çıxış kodu: $0"
        MessageBox MB_ICONSTOP|MB_OK "WinKey xidməti quraşdırılmadı (kod: $0). Quraşdırma tamamlanmadı. Detallar bölməsindəki xətanı bildirin." /SD IDOK
        SetErrorLevel 1
        Abort
    ${Else}
        DetailPrint "Sistem xidməti və təhlükəsizlik slotları uğurla hazırlandı."
    ${EndIf}

    ; Default Gateway konfiqurasiyasının yaradılması (əgər mövcud deyilsə)
    IfFileExists "C:\ProgramData\WinKey\config.json" skip_config 0
        CreateDirectory "C:\ProgramData\WinKey"
        FileOpen $1 "C:\ProgramData\WinKey\config.json" w
        FileWrite $1 '{"gateway_origin":"http://127.0.0.1:8788","pc_name":""}'
        FileClose $1
    skip_config:

    ; Qısayolların yaradılması
    DetailPrint "Start menyusu və İş masası qısayolları yaradılır..."
    CreateDirectory "$SMPROGRAMS\WinKey Pro"
    CreateShortcut "$SMPROGRAMS\WinKey Pro\WinKey Pro.lnk" "$INSTDIR\winkey_desktop.exe" "" "$INSTDIR\winkey_desktop.exe" 0
    CreateShortcut "$SMPROGRAMS\WinKey Pro\WinKey Pro Sil (Uninstall).lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
    ${If} $DesktopShortcutSelected == ${BST_CHECKED}
        CreateShortcut "$DESKTOP\WinKey Pro.lnk" "$INSTDIR\winkey_desktop.exe" "" "$INSTDIR\winkey_desktop.exe" 0
    ${Else}
        Delete "$DESKTOP\WinKey Pro.lnk"
    ${EndIf}

    ; Windows Registry (Apps & Features üçün qeydiyyat)
    DetailPrint "Windows Quraşdırılmış Proqramlar bazasında qeydiyyat aparılır..."
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

    ; İstifadəçi hər dəfə Windows-a daxil olanda tray rejimində işə düşsün
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "WinKeyPro" '"$INSTDIR\winkey_desktop.exe" --minimized'

    ; Uninstaller binarı generasiya edilir
    WriteUninstaller "$INSTDIR\uninstall.exe"

    DetailPrint "Quraşdırma müvəffəqiyyətlə başa çatdı."
SectionEnd

; ==============================================================================
; Silinmə Bölməsi (Uninstaller)
; ==============================================================================
Section "Uninstall"
    DetailPrint "WinKey Pro arxa plan xidməti dayandırılır və silinir..."
    nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$INSTDIR\service_uninstaller.ps1" -Silent -UnicodeOutput'
    Pop $0

    ; Qısayolları sil
    Delete "$DESKTOP\WinKey Pro.lnk"
    Delete "$SMPROGRAMS\WinKey Pro\WinKey Pro.lnk"
    Delete "$SMPROGRAMS\WinKey Pro\WinKey Pro Sil (Uninstall).lnk"
    RMDir "$SMPROGRAMS\WinKey Pro"

    ; Registry qeydlərini təmizlə
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "WinKeyPro"

    ; Quraşdırılmış faylları sil
    Delete "$INSTDIR\winkey_desktop.exe"
    Delete "$INSTDIR\WebView2Loader.dll"
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
