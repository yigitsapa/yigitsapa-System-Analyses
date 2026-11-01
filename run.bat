if not errorlevel 1 (
    start "yigitsapa System Analyses" python "system_analyses_gui.py"
	exit
)
echo yigitsapa System Analyses launcher was not found.
pause