# Run ARES Terminal Console on its own, outside ApexBuild. See run.sh.
Set-Location -Path $PSScriptRoot
$py = (Get-Command py -ErrorAction SilentlyContinue) ? "py" : "python"
& $py (Join-Path $PSScriptRoot "apexmod") run @args
exit $LASTEXITCODE
