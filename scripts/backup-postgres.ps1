param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
foreach ($name in 'PGHOST','PGDATABASE','PGUSER','PGPASSWORD') {
    if (-not [Environment]::GetEnvironmentVariable($name)) {
        throw "$name must be set. Credentials are read from environment variables only."
    }
}
if (-not (Get-Command pg_dump -ErrorAction SilentlyContinue)) {
    throw 'pg_dump is not installed or not available on PATH.'
}

$resolvedParent = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $resolvedParent -Force | Out-Null
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$archive = Join-Path $resolvedParent "configsentinel-$timestamp.dump"
& pg_dump --format=custom --no-owner --no-acl --file=$archive
if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE" }
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Value "$hash  $([System.IO.Path]::GetFileName($archive))" -Encoding ascii
Write-Output $archive

