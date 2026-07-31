@echo off
echo Compilation du Hasher C++...

g++ -O2 -shared -o bin/hasher.dll hasher.cpp ^
    -I"C:\Program Files\mingw64\include" ^
    -L"C:\Program Files\mingw64\lib\VC\x64\MD" ^
    -lssl -lcrypto -lws2_32

if %errorlevel% == 0 (
    echo OK : bin/hasher.dll
) else (
    echo ERREUR : hasher.dll
    goto end
)

echo.
echo Compilation du Bloom Matcher C++...

g++ -O2 -shared -o bin/bloom_matcher.dll bloom_matcher.cpp

if %errorlevel% == 0 (
    echo OK : bin/bloom_matcher.dll
) else (
    echo ERREUR : bloom_matcher.dll
)

:end



