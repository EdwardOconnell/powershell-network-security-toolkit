# Loads private helpers first, then the public commands, and exports only the public ones.
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try { . $file.FullName }
    catch { throw "Failed to load $($file.Name): $_" }
}

Export-ModuleMember -Function $public.BaseName
