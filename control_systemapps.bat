takeown /F "%ProgramFiles%\WindowsApps"
takeown /F "%ProgramFiles%\WindowsApps" /r /d y
icacls "%ProgramFiles%\WindowsApps" /grant Administrators:F
icacls "%ProgramFiles%\WindowsApps\*" /grant Administrators:F /t
icacls "%ProgramFiles%\WindowsApps" /setowner "NT Service\TrustedInstaller"
:: These lines above should give the current user full access and control over the C:\ProgramFiles\WindowsApps folder (where NonRemovable packages are provisioned for all users)
::Local user provisioned package and win store data files are in C:\Users\%username%\AppData\Local\Packages
del /s /q "%ProgramFiles%\WindowsApps"

::leave uncommented if running as a normal user or admin privleges from regular user account
del /s /q "C:\Users\%username%\AppData\Local\Packages\*"