@echo off
echo Building ForensicParserTools executable...

pyinstaller ^
    --onefile ^
    --uac-admin ^
    --name "ForensicParserTools" ^
    --hidden-import forensic_helpers ^
    --hidden-import lnk_file_parser ^
    --hidden-import prefetch_parser ^
    --hidden-import recycle_bin_parser ^
    --hidden-import timeline_correlator ^
    app.py

echo.
if exist "dist\ForensicParserTools.exe" (
    echo Build successful. Executable is at: dist\ForensicParserTools.exe
) else (
    echo Build failed. Check the output above for errors.
)
pause
