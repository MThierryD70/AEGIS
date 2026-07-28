@echo off
echo Compilation du Hasher C++...

g++ -O2 -shared -o bin/hasher.dll hasher.cpp ^
    -I"C:\Program Files\mingw64\include" ^
    -L"C:\Program Files\mingw64\lib\VC\x64\MD" ^
    -lssl -lcrypto -lws2_32

if %errorlevel% == 0 (
    echo Compilation reussie : bin/hasher.dll
) else (
    echo ERREUR de compilation
)


