@echo off
REM Build script for Windows installer

echo Building VaultKey Windows Installer...
echo Creating installer structure...
mkdir dist\windows-installer
copy dist\VaultKey.exe dist\windows-installer\
echo @echo off > dist\windows-installer\install.bat
echo echo Installing VaultKey... >> dist\windows-installer\install.bat
echo mkdir "%%LOCALAPPDATA%%\VaultKey" >> dist\windows-installer\install.bat
echo copy VaultKey.exe "%%LOCALAPPDATA%%\VaultKey\" >> dist\windows-installer\install.bat
echo setx PATH "%%PATH%%;%%LOCALAPPDATA%%\VaultKey" >> dist\windows-installer\install.bat
echo echo Installation complete! >> dist\windows-installer\install.bat
echo pause >> dist\windows-installer\install.bat
echo Done! Installer ready at dist\windows-installer\
