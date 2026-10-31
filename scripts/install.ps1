# openprotect installer - Windows form. Runs under:
#
#   irm https://kyaky.ai/openprotect/install.ps1 | iex
#
# Non-interactive by construction. Refusals are `throw`, never `exit` -
# an `exit` inside piped `iex` would kill the user's shell. Under
# `irm | iex` arguments cannot be passed, so $env:OPENPROTECT_VERSION is
# the only pin channel there; a downloaded copy also takes -Target.
#
# Environment:
#   OPENPROTECT_VERSION              pin a tag (default latest)
#   OPENPROTECT_INSTALL_DIR          override the install dir
#                                    (default %LOCALAPPDATA%\Programs\OpenProtect)
#   OPENPROTECT_SKIP_PATH_PERSIST    set to skip the user-PATH write
#
# The installed layout mirrors the archive: opc.exe, its DLLs and
# wintun.dll side by side. The tunnel itself still needs an elevated
# shell: Start-Process opc -Verb RunAs, or an admin terminal.

param([string]$Target)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AssetBase = 'https://kyaky.ai/openprotect'

# --- windows-only guard ---
# $env:OS is Windows_NT on every Windows PowerShell (5.1 and 7) and
# unset on Linux/macOS pwsh. Do NOT probe an $IsWindows variable here:
# variable names are case-insensitive, so a probe via Get-Variable
# collides with any user-defined $isWindows in scope and reads back its
# own value.
$isWinHost = ($env:OS -eq 'Windows_NT')
if (-not $isWinHost) {
	throw "openprotect: this is the Windows installer; on POSIX run: curl -fsSL $AssetBase/install.sh | sh"
}

# --- module path floor for PS 5.1 ---
if ($PSVersionTable.PSVersion.Major -le 5) {
	$env:PSModulePath = "$env:windir\System32\WindowsPowerShell\v1.0\Modules"
}

# --- version pin: explicit -Target wins over env; 'latest' or a tag ---
if (-not $PSBoundParameters.ContainsKey('Target') -and $env:OPENPROTECT_VERSION) { $Target = $env:OPENPROTECT_VERSION }
if (-not $Target) { $Target = 'latest' }
$sub = ''
if ($Target -ne 'latest') {
	if ($Target -notmatch '^v[\w.\-]+$' -or $Target -like '*..*') {
		throw "openprotect: bad version tag '$Target' (need latest or a v-tag)"
	}
	if (-not $Target.StartsWith('v')) { $Target = 'v' + $Target }
	$sub = "/$Target"
}

# --- architecture: refuse before any network call ---
switch ($env:PROCESSOR_ARCHITECTURE) {
	'AMD64' { $asset = 'openprotect-cli-windows-x86_64.zip' }
	default { throw "openprotect: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)' (this build ships windows x86_64)" }
}

# TLS floor for PS 5.1 on older builds; a no-op where TLS 1.2 is default.
try {
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$installDir = if ($env:OPENPROTECT_INSTALL_DIR) { $env:OPENPROTECT_INSTALL_DIR }
else { Join-Path $env:LOCALAPPDATA 'Programs\OpenProtect' }
$final = Join-Path $installDir 'opc.exe'

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("openprotect-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
	$zipUrl = "$AssetBase$sub/$asset"
	Write-Host "openprotect: downloading $asset ..."
	try {
		Invoke-WebRequest -UseBasicParsing -Uri $zipUrl -OutFile (Join-Path $tmp $asset)
		Invoke-WebRequest -UseBasicParsing -Uri "$zipUrl.sha256" -OutFile (Join-Path $tmp "$asset.sha256")
	} catch {
		throw "openprotect: download failed ($zipUrl): $($_.Exception.Message)"
	}

	$want = ((Get-Content (Join-Path $tmp "$asset.sha256") -TotalCount 1) -split '\s+')[0]
	$got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
	if ($want -ne $got) {
		throw "openprotect: checksum mismatch - refusing to install"
	}

	Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath (Join-Path $tmp 'unpacked') -Force
	if (-not (Test-Path (Join-Path $tmp 'unpacked\opc.exe'))) {
		throw 'openprotect: the archive has no opc.exe (asset grammar drifted?)'
	}

	New-Item -ItemType Directory -Force $installDir | Out-Null
	# Replace the whole bundle in one pass: Copy-Item each file into
	# place, then refuse a half state - a running opc.exe holds the
	# file and fails the copy loudly.
	Copy-Item (Join-Path $tmp 'unpacked\*') $installDir -Recurse -Force
	$final = Join-Path $installDir 'opc.exe'

	# --- user PATH: registry-backed, idempotent, Machine scope untouched ---
	if ($env:OPENPROTECT_SKIP_PATH_PERSIST) {
		Write-Host 'openprotect: skipping user-PATH persistence (OPENPROTECT_SKIP_PATH_PERSIST is set)'
	} else {
		$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
		if (($userPath -split ';') -notcontains $installDir) {
			$newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
			try {
				[Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
				Write-Host "openprotect: added $installDir to the user PATH (new shells pick it up)"
			} catch {
				Write-Host "openprotect: WARNING could not persist PATH; add it manually"
			}
		}
	}
	if (($env:Path -split ';') -notcontains $installDir) { $env:Path = "$env:Path;$installDir" }

	$cmd = Get-Command opc -ErrorAction SilentlyContinue
	if ($cmd -and ($cmd.Source -ne $final)) {
		Write-Host "openprotect: WARNING an existing opc resolves to $($cmd.Source) - it may keep winning PATH resolution over $final"
	}

	Write-Host "openprotect: installed $final"
	try {
		& $final --version
	} catch {
		Write-Host 'openprotect: WARNING the installed binary did not run cleanly'
	}
	Write-Host 'openprotect: next steps:'
	Write-Host '  opc connect <portal> --auth-mode headless --user <you>   # from an ADMIN shell (the tunnel needs it)'
	Write-Host '  opc status'
} finally {
	Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
