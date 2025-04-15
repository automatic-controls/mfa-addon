@echo off
setlocal
set "dfile=%root%\webapp\third-party-licenses"
if not exist "%dfile%" mkdir "%dfile%"
set "flags=--location --fail --silent --output"
set "dfile=%root%\webapp\qrcode.min.js"
if not exist "%dfile%" curl %flags% "%dfile%" "https://raw.githubusercontent.com/KeeeX/qrcodejs/refs/heads/master/qrcode.min.js"
set "dfile=%root%\webapp\third-party-licenses\qrcodejs.txt"
if not exist "%dfile%" curl %flags% "%dfile%" "https://raw.githubusercontent.com/KeeeX/qrcodejs/refs/heads/master/LICENSE"
set "dfile=%root%\webapp\third-party-licenses\otp-java.txt"
if not exist "%dfile%" curl %flags% "%dfile%" "https://raw.githubusercontent.com/BastiaanJansen/otp-java/refs/heads/main/LICENSE"
set "dfile=%root%\webapp\third-party-licenses\commons-codec.txt"
if not exist "%dfile%" curl %flags% "%dfile%" "https://raw.githubusercontent.com/apache/commons-codec/refs/heads/master/LICENSE.txt"
endlocal
exit /b