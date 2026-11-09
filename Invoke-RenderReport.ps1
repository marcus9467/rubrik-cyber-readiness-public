<#
.SYNOPSIS
    Render the Cyber Readiness report PDF from a collected bundle. Assessor-side half of the assessment.

.DESCRIPTION
    Scores bundle.json and writes report.pdf next to it. This is a thin wrapper: scoring and rendering live in
    render_pdf.py, so the PowerShell and Python paths can never drift apart. The wrapper finds Python 3, checks the
    inputs, runs render_pdf.py and, if asked, copies the PDF where you want it.

    Needs Python 3 (tested on 3.12) and, for the default brief style, Google Chrome or Chromium. Chrome is found
    automatically on Windows, macOS and Linux. Set the CHROME environment variable to use another browser. The
    classic style needs no browser but does need: pip install reportlab

    Read-only with respect to RSC. It never contacts Rubrik Security Cloud and never reads a service account.

    Runs on Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Bundle
    Path to bundle.json, or to the customer folder that holds it. Default: the newest bundle.json under ~/CyberReadiness
    (where Invoke-CyberReadiness.ps1 writes by default).

.PARAMETER OutFile
    Copy the finished PDF to this path. The original report.pdf stays next to the bundle.

.PARAMETER OutDir
    Copy the finished PDF into this folder as <customer>-report.pdf. Ignored if -OutFile is set.

.PARAMETER Style
    brief (default): HTML printed by Chrome. classic: reportlab, no browser needed.

.PARAMETER Previous
    An earlier bundle.json from the same customer. Adds a progress page.

.PARAMETER NotLicensed
    Capabilities the customer does not license: anomaly, monitoring, sdd. Comma separated. They score 0 and raise no
    finding. RSC does not report edition or license, so this is only ever what you tell it.

.PARAMETER ConfirmedActive
    Capabilities you confirmed are on everywhere but RSC did not report: anomaly, monitoring, sdd. Comma separated.
    They score 100 and the report says it was your confirmation.

.PARAMETER Open
    Open the PDF when it is done.

.EXAMPLE
    ./Invoke-RenderReport.ps1

.EXAMPLE
    ./Invoke-RenderReport.ps1 -Bundle ~/CyberReadiness/ACME -OutDir ~/Downloads -Open

.EXAMPLE
    ./Invoke-RenderReport.ps1 -Bundle ./bundle.json -NotLicensed monitoring,sdd -Previous ./earlier/bundle.json
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Bundle,
    [string]$OutFile,
    [string]$OutDir,
    [ValidateSet('brief', 'classic')][string]$Style = 'brief',
    [string]$Previous,
    [string]$NotLicensed = '',
    [string]$ConfirmedActive = '',
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Renderer = Join-Path $Here 'render_pdf.py'
$DefaultRoot = Join-Path $HOME 'CyberReadiness'

function Fail([string]$Message) {
    # Plain message and exit code. Write-Error would add a stack trace that means nothing to the person running this.
    [Console]::Error.WriteLine("ERROR: $Message")
    exit 1
}

# ---------------------------------------------------------------------------------------------------------------
# Python. Try the usual names, and check each one really is Python 3: on some machines `python` is Python 2, and on
# Windows the Store stub answers to `python` without being installed.
# ---------------------------------------------------------------------------------------------------------------

function Find-Python {
    $candidates = @(
        @{ Exe = 'python3'; Args = @() },
        @{ Exe = 'python';  Args = @() },
        @{ Exe = 'py';      Args = @('-3') }
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $ver = & $cmd.Source @($c.Args) -c 'import sys; print(sys.version_info[0])' 2>$null
            if ($LASTEXITCODE -eq 0 -and "$ver".Trim() -eq '3') { return @{ Exe = $cmd.Source; Args = $c.Args } }
        }
        catch { }
    }
    return $null
}

# ---------------------------------------------------------------------------------------------------------------
# Resolve the bundle.
# ---------------------------------------------------------------------------------------------------------------

function Resolve-Bundle([string]$Path) {
    if ($Path) {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        if (Test-Path -LiteralPath $full -PathType Container) {
            $inside = Join-Path $full 'bundle.json'
            if (-not (Test-Path -LiteralPath $inside)) { Fail "No bundle.json in folder: $full" }
            return $inside
        }
        if (-not (Test-Path -LiteralPath $full)) { Fail "Bundle not found: $full" }
        return $full
    }
    if (-not (Test-Path -LiteralPath $DefaultRoot)) {
        Fail "No -Bundle given and $DefaultRoot does not exist. Pass -Bundle <path to bundle.json or its folder>."
    }
    # Newest raw bundle. bundle.redacted.json is not a match for this name.
    $found = Get-ChildItem -LiteralPath $DefaultRoot -Filter 'bundle.json' -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $found) { Fail "No bundle.json found under $DefaultRoot. Run Invoke-CyberReadiness.ps1 first, or pass -Bundle." }
    Write-Host "Using newest bundle: $($found.FullName)"
    return $found.FullName
}

if (-not (Test-Path -LiteralPath $Renderer)) {
    Fail "render_pdf.py not found next to this script ($Here). Keep the two files together."
}

$py = Find-Python
if (-not $py) {
    Fail ("Python 3 was not found. Install it from https://www.python.org/downloads/ and run this again. " +
          "On Windows, tick 'Add python.exe to PATH' in the installer.")
}

$bundlePath = Resolve-Bundle $Bundle
if ((Split-Path -Leaf $bundlePath) -like '*redacted*') {
    Write-Warning ("This is a redacted bundle. The report will show pseudonyms (cluster-1a2b3c4d), not real names. " +
                   "Render from bundle.json if you want real names, and keep that report private.")
}

# The classic style needs reportlab. Say so up front, rather than as a Python traceback.
if ($Style -eq 'classic') {
    & $py.Exe @($py.Args) -c 'import reportlab' 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "The classic style needs reportlab. Run: pip install reportlab" }
}

# Chrome for the brief style. render_pdf.py finds Chrome itself; this only warns early with a clear message.
if ($Style -eq 'brief') {
    $chromeOk = $false
    if ($env:CHROME -and (Test-Path -LiteralPath $env:CHROME)) { $chromeOk = $true }
    if (-not $chromeOk) {
        $known = @(
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
        )
        if ($known | Where-Object { Test-Path -LiteralPath $_ }) { $chromeOk = $true }
        foreach ($n in 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'chrome') {
            if (Get-Command $n -ErrorAction SilentlyContinue) { $chromeOk = $true }
        }
    }
    if (-not $chromeOk) {
        Fail ("Google Chrome or Chromium was not found. Install Chrome, set the CHROME environment variable to its " +
              "path, or use -Style classic (needs: pip install reportlab).")
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Render.
# ---------------------------------------------------------------------------------------------------------------

$renderArgs = @($Renderer, '--bundle', $bundlePath, '--style', $Style)
if ($Previous)        { $renderArgs += @('--previous', $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Previous)) }
if ($NotLicensed)     { $renderArgs += @('--not-licensed', $NotLicensed) }
if ($ConfirmedActive) { $renderArgs += @('--confirmed-active', $ConfirmedActive) }

Write-Host "Rendering $bundlePath ..."
# Windows PowerShell 5.1 turns a native command's stderr into a terminating error when 2>&1 is used under 'Stop',
# which would end the script before it could print the renderer's own message. Relax it for this one call and
# judge success by the exit code instead.
$ErrorActionPreference = 'Continue'
$output = & $py.Exe @($py.Args) @renderArgs 2>&1
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$output | ForEach-Object { Write-Host $_ }
if ($code -ne 0) { Fail "render_pdf.py failed with exit code $code. The message above says why." }

$report = Join-Path (Split-Path -Parent $bundlePath) 'report.pdf'
if (-not (Test-Path -LiteralPath $report)) { Fail "The renderer reported success but $report is missing." }

# ---------------------------------------------------------------------------------------------------------------
# Deliver.
# ---------------------------------------------------------------------------------------------------------------

$final = $report
if ($OutFile) {
    $final = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
}
elseif ($OutDir) {
    $dir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
    $customer = Split-Path -Leaf (Split-Path -Parent $bundlePath)
    $final = Join-Path $dir "$customer-report.pdf"
}
if ($final -ne $report) {
    $parent = Split-Path -Parent $final
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (Test-Path -LiteralPath $final) { Write-Warning "Overwriting $final" }
    Copy-Item -LiteralPath $report -Destination $final -Force
}

Write-Host "Report: $final"
if ($Open) {
    if ($IsMacOS) { & open $final }
    elseif ($IsLinux) { & xdg-open $final }
    else { Start-Process -FilePath $final }
}
