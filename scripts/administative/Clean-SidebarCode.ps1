[CmdletBinding(DefaultParameterSetName = "Output")]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InputPath,

    [Parameter(Position = 1, ParameterSetName = "Output")]
    [string]$OutputPath,

    [Parameter(Mandatory = $true, ParameterSetName = "InPlace")]
    [switch]$InPlace,

    [switch]$NoBackup,
    [switch]$SkipValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-TextRobust {
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)

    try {
        $utf8Strict = [System.Text.UTF8Encoding]::new($true, $true)
        return $utf8Strict.GetString($bytes)
    }
    catch {
        $cp1252 = [System.Text.Encoding]::GetEncoding(1252)
        return $cp1252.GetString($bytes)
    }
}

function ConvertFrom-RepeatedHtmlEncoding {
    param([Parameter(Mandatory = $true)][string]$Text)

    for ($index = 0; $index -lt 8; $index++) {
        $decoded = [System.Net.WebUtility]::HtmlDecode($Text)
        if ($decoded -ceq $Text) {
            break
        }
        $Text = $decoded
    }

    return $Text
}

function Remove-SidebarHtml {
    param([Parameter(Mandatory = $true)][string]$Text)

    $Text = $Text.TrimStart([char]0xFEFF)
    $Text = $Text.Replace([char]0x00A0, ' ')
    $Text = $Text.Replace([string][char]0x200B, '')
    $Text = $Text.Replace([string][char]0x200C, '')
    $Text = $Text.Replace([string][char]0x200D, '')

    $Text = ConvertFrom-RepeatedHtmlEncoding -Text $Text

    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $Text = [regex]::Replace(
        $Text,
        '<\s*br(?:\s+[^>]*)?/?>',
        "`n",
        $regexOptions
    )
    $Text = [regex]::Replace(
        $Text,
        '<\s*/?\s*(?:pre|code|span|div)(?:\s+[^>]*)?>',
        '',
        $regexOptions
    )

    $Text = ConvertFrom-RepeatedHtmlEncoding -Text $Text
    $Text = [regex]::Replace(
        $Text,
        '<\s*br(?:\s+[^>]*)?/?>',
        "`n",
        $regexOptions
    )
    $Text = [regex]::Replace(
        $Text,
        '<\s*/?\s*(?:pre|code|span|div)(?:\s+[^>]*)?>',
        '',
        $regexOptions
    )

    $multilineIgnoreCase = (
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    )
    $Text = [regex]::Replace(
        $Text,
        '^[ \t]*```(?:python|py|powershell|ps1)?[ \t]*$',
        '',
        $multilineIgnoreCase
    )

    $Text = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    return $Text.Trim("`n") + "`n"
}

$source = [System.IO.Path]::GetFullPath($InputPath)
if (-not [System.IO.File]::Exists($source)) {
    throw "Invoerbestand bestaat niet: $source"
}

if ($InPlace) {
    $destination = $source
}
elseif ($OutputPath) {
    $destination = [System.IO.Path]::GetFullPath($OutputPath)
}
else {
    $directory = [System.IO.Path]::GetDirectoryName($source)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($source)
    $extension = [System.IO.Path]::GetExtension($source)
    $destination = [System.IO.Path]::Combine(
        $directory,
        "$stem.clean$extension"
    )
}

if (($destination -eq $source) -and (-not $InPlace)) {
    throw "Gebruik -InPlace om het bronbestand te overschrijven."
}

if ($InPlace -and (-not $NoBackup)) {
    $backup = "$source.bak"
    [System.IO.File]::Copy($source, $backup, $true)
    Write-Host "[OK] Back-up: $backup"
}

$text = Read-TextRobust -Path $source
$cleaned = Remove-SidebarHtml -Text $text

$destinationDirectory = [System.IO.Path]::GetDirectoryName($destination)
if (-not [string]::IsNullOrWhiteSpace($destinationDirectory)) {
    [System.IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($destination, $cleaned, $utf8NoBom)
Write-Host "[OK] UTF-8-uitvoer: $destination"

$isPython = [System.IO.Path]::GetExtension($destination) -ieq '.py'
if ($isPython -and (-not $SkipValidation)) {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        Write-Warning "Python niet gevonden; syntaxcontrole overgeslagen."
    }
    else {
        & python -m py_compile $destination
        if ($LASTEXITCODE -ne 0) {
            Write-Error (
                "HTML is opgeschoond, maar Python-syntax is nog ongeldig. " +
                "Het opgeschoonde bestand is wel bewaard."
            )
            exit 1
        }
        Write-Host "[OK] Python-syntaxcontrole geslaagd."
    }
}
