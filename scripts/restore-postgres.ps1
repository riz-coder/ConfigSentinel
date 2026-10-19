param(
    [Parameter(Mandatory = $true)] [string]$Archive,
    [Parameter(Mandatory = $true)] [string]$ConfirmTarget
)

$ErrorActionPreference = 'Stop'
foreach ($name in 'PGHOST','PGDATABASE','PGUSER','PGPASSWORD') {
    if (-not [Environment]::GetEnvironmentVariable($name)) { throw "$name must be set." }
}
if ($ConfirmTarget -cne $env:PGDATABASE) {
    throw "ConfirmTarget must exactly match PGDATABASE ('$env:PGDATABASE')."
}
$resolvedArchive = (Resolve-Path -LiteralPath $Archive).Path
$hashFile = "$resolvedArchive.sha256"
if (-not (Test-Path -LiteralPath $hashFile)) { throw "Missing checksum file: $hashFile" }
$expected = ((Get-Content -LiteralPath $hashFile -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedArchive).Hash.ToLowerInvariant()
if ($actual -cne $expected.ToLowerInvariant()) { throw 'Backup SHA-256 verification failed.' }
if (-not (Get-Command pg_restore -ErrorAction SilentlyContinue)) { throw 'pg_restore is not available on PATH.' }
& pg_restore --clean --if-exists --no-owner --no-acl --exit-on-error --dbname=$env:PGDATABASE $resolvedArchive
if ($LASTEXITCODE -ne 0) { throw "pg_restore failed with exit code $LASTEXITCODE" }
Write-Output "Restore completed for $env:PGDATABASE"

