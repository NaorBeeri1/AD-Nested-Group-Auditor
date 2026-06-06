# Advanced Members Of
param([string]$Identity)

cls
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Error "ActiveDirectory module not found. Install RSAT or run on a DC/management host."; exit }

# Input
if (-not $Identity -or $Identity.Trim() -eq '') {
    $Identity = Read-Host "Enter Username (sAMAccountName or UPN)"
}
$safeUser  = ($Identity -replace '[\\/:*?"<>|]', '_').Trim()
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Domains
$forest = Get-ADForest
$forestDomains = $forest.Domains
if (-not $forestDomains -or $forestDomains.Count -eq 0) { Write-Error "No domains found in forest."; exit }

$user=$null; $userDN=$null; $userHome=$null
foreach ($dom in $forestDomains) {
    try {
        $candidate = Get-ADUser -Identity $Identity -Server $dom -Properties * -ErrorAction Stop
        if ($candidate) { $user=$candidate; $userDN=$candidate.DistinguishedName; $userHome=$dom; break }
    } catch {}
}
if (-not $user) { Write-Host "User '$Identity' not found in any domain." -ForegroundColor Red; exit }

Write-Host "User found in: $userHome" -ForegroundColor Cyan
Write-Host "DistinguishedName: $userDN`n"
$idShown = if ($user.userPrincipalName) { $user.userPrincipalName } else { $user.sAMAccountName }

# CSV
Write-Host "Collecting direct groups for CSV..." -ForegroundColor Yellow
$data = @()
foreach ($domain in $forestDomains) {
    try {
        $all = Get-ADObject -LDAPFilter "(member=$userDN)" -Server $domain -Properties sAMAccountName, CanonicalName |
               Select-Object sAMAccountName, CanonicalName, DistinguishedName
        if ($all) { $data += $all }
    } catch {}
}

if ($data.Count -gt 0) {
    $data = $data | Sort-Object DistinguishedName -Unique | Select-Object sAMAccountName, CanonicalName
} else {
    Write-Host "No direct groups found for CSV." -ForegroundColor Yellow
}

# Paths
$outDir  = [System.IO.Path]::GetTempPath()
$base    = "{0}_{1}" -f $safeUser, $timestamp
$csvPath = Join-Path $outDir ($base + ".csv")

# CSV Export
$data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "CSV saved to: $csvPath" -ForegroundColor Green

# TXT nested tree
Add-Type -AssemblyName System.Collections
$VisitedGroups = [System.Collections.Generic.HashSet[string]]::new()

function Get-DomainFromDN {
    param([Parameter(Mandatory)][string]$DN)
    $dcParts = ([regex]::Matches($DN,'DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value })
    if ($dcParts.Count -gt 0) { return ($dcParts -join '.') }
    return $null
}

$gcServer = $null
if ($forest.GlobalCatalogs -and $forest.GlobalCatalogs.Count -gt 0) { $gcServer = $forest.GlobalCatalogs[0] + ":3268" }

function Get-GroupByDN {
    param([Parameter(Mandatory)][string]$GroupDN)
    $dom = Get-DomainFromDN -DN $GroupDN
    if ($dom) {
        try { return Get-ADGroup -Identity $GroupDN -Server $dom -Properties distinguishedName,name,sAMAccountName,canonicalName,memberOf -ErrorAction Stop } catch {}
    }
    if ($gcServer) {
        try {
            $obj = Get-ADObject -Identity $GroupDN -Server $gcServer -Properties distinguishedName,name,sAMAccountName,canonicalName,memberOf,objectClass -ErrorAction Stop
            if ($obj -and $obj.objectClass -eq 'group') { return $obj }
        } catch {}
    }
    return $null
}

function Get-DisplayName {
    param([Parameter(Mandatory)]$GroupObj)
    if ($GroupObj.Name) { return [string]$GroupObj.Name }
    if ($GroupObj.DistinguishedName) {
        $m = [regex]::Match($GroupObj.DistinguishedName,'^CN=([^,]+)')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return '<unknown>'
}

function Resolve-PrimaryGroup {
    param([Parameter(Mandatory)]$User)
    if ($null -eq $User.objectSid -or $null -eq $User.primaryGroupID) { return $null }
    try {
        $sid       = New-Object System.Security.Principal.SecurityIdentifier($User.objectSid,0)
        $sidParts  = $sid.Value.Split('-')
        $domainSid = ($sidParts[0..($sidParts.Length-2)] -join '-')
        $pgSid     = "$domainSid-$($User.primaryGroupID)"
        return Get-ADObject -LDAPFilter "(objectSid=$pgSid)" -Server $userHome `
            -Properties distinguishedName,name,sAMAccountName,canonicalName,objectClass,memberOf -ErrorAction SilentlyContinue
    } catch { return $null }
}

$directGroups = @()
foreach ($dom in $forestDomains) {
    try {
        $g = Get-ADGroup -LDAPFilter "(member=$userDN)" -Server $dom `
            -Properties distinguishedName,name,sAMAccountName,canonicalName,memberOf -ErrorAction SilentlyContinue
        if ($g) { $directGroups += $g }
    } catch {}
}
$pg = Resolve-PrimaryGroup -User $user
if ($pg -and $pg.objectClass -eq 'group' -and -not ($directGroups | Where-Object { $_.DistinguishedName -eq $pg.DistinguishedName })) {
    $directGroups += $pg
}
$directGroups = $directGroups | Sort-Object DistinguishedName -Unique

# Console Preview
if ($directGroups.Count -gt 0) {
    $directGroups |
        Select-Object @{n='sAMAccountName';e={$_.sAMAccountName}},
                      @{n='CanonicalName'; e={$_.CanonicalName}} |
        Format-Table -AutoSize -Wrap
} else {
    Write-Host "No direct groups found for TXT tree." -ForegroundColor Yellow
}

function Make-BulletLine {
    param([int]$Level,[string]$Text)
    if ($Level -lt 1) { $Level = 1 }
    $hyphens = ('-' * $Level)
    return "$hyphens $Text"
}

$TreeLines = New-Object System.Collections.Generic.List[string]
$TreeLines.Add("== User Members Of Nested ==") | Out-Null
$TreeLines.Add("User:  " + $idShown) | Out-Null
$TreeLines.Add("") | Out-Null

function Walk-Parents {
    param(
        [Parameter(Mandatory)]$GroupObj,
        [int]$Level,
        [string]$Path
    )
    $dn = $GroupObj.DistinguishedName
    if ($VisitedGroups.Contains($dn)) { return }
    $VisitedGroups.Add($dn) | Out-Null

    $name = Get-DisplayName -GroupObj $GroupObj
    $TreeLines.Add( (Make-BulletLine -Level $Level -Text $name) ) | Out-Null

    foreach ($parentDN in @($GroupObj.memberOf)) {
        $p = Get-GroupByDN -GroupDN $parentDN
        if ($p) { Walk-Parents -GroupObj $p -Level ($Level + 1) -Path ($Path + " -> " + $name) }
    }
}

if ($directGroups.Count -eq 0) {
    $TreeLines.Add("- (No direct groups to expand)") | Out-Null
} else {
    foreach ($g in $directGroups) {
        $VisitedGroups.Clear() | Out-Null
        $TreeLines.Add( (Make-BulletLine -Level 1 -Text (Get-DisplayName $g)) ) | Out-Null
        foreach ($parentDN in @($g.memberOf)) {
            $p = Get-GroupByDN -GroupDN $parentDN
            if ($p) { Walk-Parents -GroupObj $p -Level 2 -Path (Get-DisplayName $g) }
        }
        $TreeLines.Add("") | Out-Null
    }
}

# %TEMP%
$txtPath = Join-Path $outDir ($base + "-nested-groups.txt")
$TreeLines | Out-File -FilePath $txtPath -Encoding UTF8

Write-Host "`nTXT saved to: $txtPath" -ForegroundColor Green

# Open
Start-Process notepad.exe -ArgumentList $txtPath
Start-Process -FilePath $csvPath

Write-Host "`nDone. Files in %TEMP%:`n  CSV: $csvPath`n  TXT: $txtPath"
pause