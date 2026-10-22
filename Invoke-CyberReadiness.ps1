<#
.SYNOPSIS
    Rubrik Cyber Readiness collector for PowerShell. Customer-side half of the assessment.

.DESCRIPTION
    Read-only. Issues GraphQL queries against Rubrik Security Cloud (RSC) with a service account and writes
    bundle.json (raw), plus bundle.redacted.json and redaction-map.json when -Redact is set.
    The bundle schema is identical to the Python collector (collect.py), so the assessor renders the report
    from either one with render_pdf.py.

    Runs on Windows PowerShell 5.1 and PowerShell 7+. No modules to install.

.PARAMETER ServiceAccount
    Path to the service account JSON downloaded from RSC (client_id, client_secret, access_token_uri).

.PARAMETER Customer
    Short label used for the output folder and the report. Required unless -Preflight.

.PARAMETER Out
    Output directory. Default: ~/CyberReadiness

.PARAMETER Redact
    Also write bundle.redacted.json (safe to send) and redaction-map.json (keep, do not send).

.PARAMETER Preflight
    Run every collector once and report which sections the role can and cannot read. Writes nothing.
    Exit code 0 if everything was readable, 1 otherwise.

.EXAMPLE
    ./Invoke-CyberReadiness.ps1 -ServiceAccount ~/.rubrik/assessment.json -Preflight

.EXAMPLE
    ./Invoke-CyberReadiness.ps1 -ServiceAccount ~/.rubrik/assessment.json -Customer ACME -Redact
#>
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
    [Parameter(Mandatory, Position = 0)][Alias('Sa')][string]$ServiceAccount,
    [Parameter(ParameterSetName = 'Collect', Mandatory)][string]$Customer,
    [Parameter(ParameterSetName = 'Collect')][string]$Out = (Join-Path $HOME 'CyberReadiness'),
    [Parameter(ParameterSetName = 'Collect')][switch]$Redact,
    [Parameter(ParameterSetName = 'Preflight', Mandatory)][switch]$Preflight
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# ---------------------------------------------------------------------------------------------------------------
# Small helpers. The bundle mixes API objects (PSCustomObject) and our own ordered dictionaries, so property
# access goes through these.
# ---------------------------------------------------------------------------------------------------------------

function Get-Prop($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $null }
    # Plain assignments, not `$v = if {...}`: an if-expression unrolls a one-element array into its element.
    # Redaction relies on `-is [Array]` to find service accounts, IdPs and roles, and a customer with a single
    # one of them would otherwise be left unredacted.
    if ($Obj -is [System.Collections.IDictionary]) { $v = $Obj[$Name] } else { $v = $Obj.$Name }
    # Same for the return: function output is unrolled, so wrap arrays to hand them back intact.
    if ($v -is [System.Array]) { return , $v }
    return $v
}

function Test-Prop($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $false }
    if ($Obj -is [System.Collections.IDictionary]) { return $Obj.Contains($Name) }
    return [bool]($Obj.PSObject.Properties.Name -contains $Name)
}

function Set-Prop($Obj, [string]$Name, $Value) {
    if ($Obj -is [System.Collections.IDictionary]) { $Obj[$Name] = $Value }
    else { Add-Member -InputObject $Obj -NotePropertyName $Name -NotePropertyValue $Value -Force }
}

function Remove-Prop($Obj, [string]$Name) {
    if ($Obj -is [System.Collections.IDictionary]) { $Obj.Remove($Name) }
    else { [void]$Obj.PSObject.Properties.Remove($Name) }
}

function Get-PropNames($Obj) {
    if ($Obj -is [System.Collections.IDictionary]) { return @($Obj.Keys) }
    return @($Obj.PSObject.Properties.Name)
}

function Test-IsMap($Obj) {
    return ($Obj -is [System.Collections.IDictionary]) -or ($Obj -is [System.Management.Automation.PSCustomObject])
}

# Python truthiness for a list: null and empty are false.
function Test-Any($List) { return ($null -ne $List) -and (@($List).Count -gt 0) }

# Python `value is True` / `is False`: a real boolean only. null (unknown) matches neither.
function Test-Is($Value, [bool]$Want) { return ($Value -is [bool]) -and ($Value -eq $Want) }

function Get-List($Value) { if ($null -eq $Value) { return @() } else { return @($Value) } }

function Get-Str($Value) { if ($null -eq $Value) { return '' } else { return [string]$Value } }

# {key, count} rows, most common first, ties in first-seen order (Python Counter.most_common).
function Get-Tally($Keys, [int]$Top = 0) {
    $counts = [ordered]@{}
    foreach ($k in $Keys) {
        $ks = if ($null -eq $k) { '' } else { [string]$k }
        $counts[$ks] = 1 + [int]$counts[$ks]
    }
    $i = 0
    $rows = foreach ($k in $counts.Keys) { [pscustomobject]@{ key = $k; count = $counts[$k]; i = $i++ } }
    $sorted = @($rows | Sort-Object -Property @{ Expression = 'count'; Descending = $true }, @{ Expression = 'i' })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $sorted) {
        if ($Top -gt 0 -and $out.Count -ge $Top) { break }
        $out.Add([ordered]@{ key = $r.key; count = $r.count })
    }
    return , $out.ToArray()
}

function Get-SortedOrdinal($Items) {
    $arr = [string[]]@($Items | Where-Object { $null -ne $_ } | Select-Object -Unique)
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    return , $arr
}

function Get-Sum($Items) {
    $t = 0
    foreach ($i in $Items) { if ($null -ne $i) { $t += $i } }
    return $t
}

function Get-IsoUtc([datetime]$When) {
    return $When.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'.000Z'", [Globalization.CultureInfo]::InvariantCulture)
}

# Windows PowerShell and PowerShell 7 both turn ISO timestamps into DateTime objects when parsing JSON, which then
# re-serialize in a different shape. Prefix them with a marker on the way in and strip it on the way out so every
# timestamp stays the exact string RSC returned.
$script:DateMark = '~~'
$script:IsoDateRe = [regex]'"(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)"'

function ConvertTo-BundleJson($Object) {
    $text = ConvertTo-Json -InputObject $Object -Depth 100
    # Windows PowerShell 5.1 escapes the apostrophe as '; put it back so the JSON matches the Python bundle.
    $escaped = [string][char]92 + 'u0027'
    return $text.Replace($escaped, [string][char]39)
}

function Remove-DateMark([string]$Text) { return $Text.Replace('"' + $script:DateMark, '"') }

function Write-Utf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Resolve-UserPath([string]$Path) {
    if ($Path -eq '~') { return $HOME }
    if ($Path.StartsWith('~/') -or $Path.StartsWith('~\')) { return Join-Path $HOME $Path.Substring(2) }
    return $Path
}

# ---------------------------------------------------------------------------------------------------------------
# RSC client: service account auth, retries, auto-pagination. GraphQL queries only. There are no mutations here.
# ---------------------------------------------------------------------------------------------------------------

function Send-Http([string]$Uri, $Body, [string]$ContentType, [hashtable]$Headers) {
    $params = @{ Uri = $Uri; Method = 'POST'; UseBasicParsing = $true; TimeoutSec = 120 }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($Headers) { $params.Headers = $Headers }
    if ($null -ne $Body) { $params.Body = $Body }
    try {
        $r = Invoke-WebRequest @params
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Text = [string]$r.Content }
    }
    catch {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $text = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $text = $_.ErrorDetails.Message }
        elseif ($resp.GetResponseStream) {
            try { $text = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch { }
        }
        return [pscustomobject]@{ Status = [int]$resp.StatusCode; Text = $text }
    }
}

function Connect-Rsc([string]$SaPath) {
    $sa = Get-Content -Raw -LiteralPath (Resolve-UserPath $SaPath) | ConvertFrom-Json
    $client = @{
        ClientId = $sa.client_id; ClientSecret = $sa.client_secret; TokenUrl = $sa.access_token_uri
        GqlUrl   = ([string]$sa.access_token_uri).Replace('/api/client_token', '/api/graphql')
        Token    = $null; Expiry = [datetime]::MinValue
    }
    Update-RscToken $client
    return $client
}

function Update-RscToken($Client) {
    $form = 'grant_type=client_credentials&client_id={0}&client_secret={1}' -f
        [uri]::EscapeDataString($Client.ClientId), [uri]::EscapeDataString($Client.ClientSecret)
    $r = Send-Http $Client.TokenUrl $form 'application/x-www-form-urlencoded' $null
    if ($r.Status -ne 200) {
        $snippet = $r.Text.Substring(0, [Math]::Min(200, $r.Text.Length))
        throw "Auth failed ($($r.Status)): $snippet"
    }
    $body = $r.Text | ConvertFrom-Json
    $ttl = if ($body.expires_in) { [int]$body.expires_in } else { 3600 }
    $Client.Token = $body.access_token
    $Client.Expiry = (Get-Date).AddSeconds($ttl - 60)
}

# 2, 4, 8, 16 seconds, capped at 30. A slow page on a large tenant needs room to recover.
function Get-Backoff([int]$Attempt) { return [Math]::Min([Math]::Pow(2, $Attempt + 1), 30) }

function Invoke-RscQuery($Client, [string]$Gql, $Variables = @{}, [int]$Retries = 5) {
    if ((Get-Date) -gt $Client.Expiry) { Update-RscToken $Client }
    $payload = ConvertTo-Json -InputObject ([ordered]@{ query = $Gql; variables = $Variables }) -Depth 20
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $headers = @{ Authorization = "Bearer $($Client.Token)" }
    for ($attempt = 0; $attempt -lt $Retries; $attempt++) {
        # Timeouts and connection errors have no response, so Send-Http throws. Retry them like 429 and 5xx.
        try { $r = Send-Http $Client.GqlUrl $bytes 'application/json' $headers }
        catch {
            if ($attempt -lt $Retries - 1) { Start-Sleep -Seconds (Get-Backoff $attempt); continue }
            throw "request failed after $Retries attempts: $($_.Exception.Message)"
        }
        if (@(429, 502, 503, 504) -contains $r.Status -and $attempt -lt $Retries - 1) {
            Start-Sleep -Seconds (Get-Backoff $attempt); continue
        }
        if ($r.Status -ne 200) {
            throw "HTTP $($r.Status): $($r.Text.Substring(0, [Math]::Min(300, $r.Text.Length)))"
        }
        $marked = $script:IsoDateRe.Replace($r.Text, '"' + $script:DateMark + '$1"')
        $body = $marked | ConvertFrom-Json
        if ($body.errors -and -not $body.data) {
            $e = ConvertTo-Json -InputObject $body.errors -Depth 20 -Compress
            throw $e.Substring(0, [Math]::Min(500, $e.Length))
        }
        if ($null -eq $body.data) { return [pscustomobject]@{} }
        return $body.data
    }
    throw 'retries exhausted'
}

# Walks a connection. $Gql must declare $after and select pageInfo. $Path is the dotted route, e.g. 'slaDomains'.
function Invoke-RscPaginate($Client, [string]$Gql, [string]$Path, $Variables = @{}) {
    $nodes = New-Object System.Collections.Generic.List[object]
    $after = $null
    $pages = 0
    while ($true) {
        $vars = @{}
        foreach ($k in $Variables.Keys) { $vars[$k] = $Variables[$k] }
        $vars['after'] = $after
        $conn = Invoke-RscQuery $Client $Gql $vars
        foreach ($key in $Path.Split('.')) { $conn = $conn.$key }
        if ($null -eq $conn) { throw "no connection at '$Path' in the response" }
        foreach ($n in @($conn.nodes)) { if ($null -ne $n) { $nodes.Add($n) } }
        $pages++
        if ($pages % 10 -eq 0) {
            $of = if ($conn.count) { " of $($conn.count)" } else { '' }
            Write-Host "  ${Path}: $($nodes.Count)$of records, $pages pages"
        }
        if (-not $conn.pageInfo.hasNextPage) { return , $nodes.ToArray() }
        $after = $conn.pageInfo.endCursor
    }
}

# ---------------------------------------------------------------------------------------------------------------
# RBAC permission summary (port of rbac.summarize_permissions).
# ---------------------------------------------------------------------------------------------------------------

function Get-PermissionSummary($Perms) {
    $ops = New-Object System.Collections.Generic.HashSet[string]
    $global = $false
    foreach ($p in (Get-List $Perms)) {
        if ($null -ne $p.operation) { [void]$ops.Add([string]$p.operation) }
        foreach ($h in (Get-List $p.objectsForHierarchyTypes)) {
            foreach ($oid in (Get-List $h.objectIds)) {
                if ($oid -eq 'GlobalResource' -or ([string]$oid).EndsWith('_ROOT')) { $global = $true }
            }
        }
    }
    return @{ operations = (Get-SortedOrdinal $ops); globalScope = $global }
}

# ---------------------------------------------------------------------------------------------------------------
# Collectors. Each takes the client and returns the section for bundle.data.<name>.
# ---------------------------------------------------------------------------------------------------------------

function Get-RcIdentity($Client) {
    $q = @'
query Users($after: String) {
  usersInCurrentAndDescendantOrganization(
    after: $after
    filter: {emailFilter: "", lockoutStateFilter: ALL, hiddenStateFilter: NOT_HIDDEN}
    shouldIncludeUserWithoutRole: true
  ) {
    count
    nodes {
      id email domain status isAccountOwner lastLogin
      totpStatus { isEnabled isEnforced isEnforcedUserLevel isSupported mfaStatus }
      roles { id name isReadOnly isOrgAdmin }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    return [ordered]@{ users = (Invoke-RscPaginate $Client $q 'usersInCurrentAndDescendantOrganization') }
}

function Get-RcMfa($Client) {
    $q = @'
query Mfa {
  mfaSetting {
    isTotpEnforcedGlobal isTotpGlobalEnforceLocked isTotpMandatory
    mandatoryTotpEnforcementDate mfaRememberHours totpReminderHours
  }
}
'@
    return (Invoke-RscQuery $Client $q).mfaSetting
}

function Get-RcQuorum($Client) {
    $orgsQ = 'query { currentUser { allOrgs { id name } } }'
    $cfgQ = @'
query Tpr($orgId: String!) {
  tprConfiguration(orgId: $orgId) {
    isTprEnabled staticQuorumRequirement requestTimeoutHours
    executionMaxTimeoutHours reminderHours
  }
}
'@
    $polQ = @'
query Policies($after: String) {
  customTprPolicies(after: $after) {
    count
    nodes {
      policyId policyName orgId orgName quorumRequirement
      numberOfObjectTypes numberOfProtectableObjects
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    # A service account can return an empty allOrgs, so also take org ids from the policies.
    $orgs = [ordered]@{}
    foreach ($o in (Get-List (Invoke-RscQuery $Client $orgsQ).currentUser.allOrgs)) { $orgs[[string]$o.id] = $o.name }
    $policies = Invoke-RscPaginate $Client $polQ 'customTprPolicies'
    foreach ($p in $policies) { if (-not $orgs.Contains([string]$p.orgId)) { $orgs[[string]$p.orgId] = $p.orgName } }
    $config = [ordered]@{}
    foreach ($oid in @($orgs.Keys)) {
        $config[$oid] = (Invoke-RscQuery $Client $cfgQ @{ orgId = $oid }).tprConfiguration
    }
    return [ordered]@{ orgs = $orgs; config = $config; policies = $policies }
}

function Get-RcSla($Client) {
    $q = @'
query Slas($after: String) {
  slaDomains(after: $after, first: 200, shouldShowProtectedObjectCount: true) {
    count
    nodes {
      id name
      ... on GlobalSlaReply {
        isRetentionLockedSla retentionLockMode protectedObjectCount objectTypes
        isDefault isArchived
        archivalSpecs { isComplianceImmutabilityEnabled threshold thresholdUnit }
        replicationSpecsV2 { retentionDuration { duration unit } }
        baseFrequency { duration unit }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $slas = Invoke-RscPaginate $Client $q 'slaDomains'
    # Skip the pseudo-SLAs RSC returns for unprotected / do-not-protect, they have no config.
    $real = @($slas | Where-Object { (Test-Prop $_ 'isRetentionLockedSla') -and -not $_.isArchived })
    $locked = @($real | Where-Object { $_.isRetentionLockedSla })
    $inUse = @($real | Where-Object { $_.protectedObjectCount -gt 0 })
    return [ordered]@{
        total                = $real.Count
        retentionLocked      = $locked.Count
        inUse                = $inUse.Count
        inUseLocked          = @($inUse | Where-Object { $_.isRetentionLockedSla }).Count
        objectsOnLockedSlas  = Get-Sum ($locked | ForEach-Object { $_.protectedObjectCount })
        objectsOnAnySla      = Get-Sum ($real | ForEach-Object { $_.protectedObjectCount })
        withArchival         = @($real | Where-Object { Test-Any $_.archivalSpecs }).Count
        withImmutableArchival = @($real | Where-Object {
                @(Get-List $_.archivalSpecs | Where-Object { $_.isComplianceImmutabilityEnabled }).Count -gt 0
            }).Count
        withReplication      = @($real | Where-Object { Test-Any $_.replicationSpecsV2 }).Count
        lockModes            = Get-Tally ($real | ForEach-Object { $_.retentionLockMode })
        slas                 = $real
    }
}

function Get-RcAccess($Client) {
    $queries = [ordered]@{
        ipAllowlist       = @('query { ipWhitelist { enabled mode ipCidrs } }', 'ipWhitelist')
        lockout           = @(@'
query { lockoutConfig {
  isBruteForceLockoutEnabled loginAttemptsLimit isAutoUnlockFeatureEnabled
  accountAutoUnlockDurationInMins
  inactiveLockoutConfig { isInactiveLockoutEnabled inactivityDaysLimit }
} }
'@, 'lockoutConfig')
        session           = @(@'
query { userSessionManagementConfig { config {
  isInactivityTimeoutEnabled inactivityTimeoutInSeconds sessionTimeoutInSeconds
  isConcurrentSessionLimitationEnabled maxConcurrentSessions isGlobalPolicyEnforced
} } }
'@, 'userSessionManagementConfig.config')
        passwordPolicy    = @(@'
query { passwordComplexityPolicy {
  lengthPolicy { defaultValue isActive minValue }
  uppercasePolicy { defaultValue isActive }
  lowercasePolicy { defaultValue isActive }
  numericPolicy { defaultValue isActive }
  specialCharsPolicy { defaultValue isActive }
  passwordExpirationPolicy { defaultValue isActive }
  passwordReusePolicy { defaultValue isActive }
  leakedDetectionPolicy { isActive }
} }
'@, 'passwordComplexityPolicy')
        # A boolean, not allCurrentOrgIdentityProviders: the full provider record includes fields that need the
        # "Manage LDAP and SSO" permission (MANAGE_AUTH_DOMAIN), and rule A-3 only asks whether any exists.
        hasIdp            = @('query { hasIdpConfigured }', 'hasIdpConfigured')
        serviceAccounts   = @('query { serviceAccounts { nodes { name clientId lastLogin roles { name } } } }',
            'serviceAccounts.nodes')
    }
    $rolesQ = @'
query Roles($after: String) {
  getAllRolesInOrgConnection(after: $after, first: 200) {
    count
    nodes { id name description isReadOnly isOrgAdmin }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    # Same query plus each role's effective permissions (operation + object scope).
    $rolesPermsQ = @'
query Roles($after: String) {
  getAllRolesInOrgConnection(after: $after, first: 200) {
    count
    nodes {
      id name description isReadOnly isOrgAdmin
      effectivePermissions { operation objectsForHierarchyTypes { snappableType objectIds } }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $groupsQ = @'
query Groups($after: String) {
  groupsInCurrentAndDescendantOrganization(after: $after, first: 100, shouldIncludeGroupsWithoutRole: true) {
    count
    nodes { groupId groupName domainName roles { id name } users { id domain } }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $out = [ordered]@{}
    foreach ($key in $queries.Keys) {
        try {
            $node = Invoke-RscQuery $Client $queries[$key][0]
            foreach ($seg in $queries[$key][1].Split('.')) { $node = $node.$seg }
            $out[$key] = $node
        }
        catch { $out[$key] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    }
    try {
        $roles = Invoke-RscPaginate $Client $rolesPermsQ 'getAllRolesInOrgConnection'
        $out['roles'] = @(foreach ($r in $roles) {
                $rec = [ordered]@{}
                foreach ($n in (Get-PropNames $r)) { if ($n -ne 'effectivePermissions') { $rec[$n] = $r.$n } }
                $sum = Get-PermissionSummary $r.effectivePermissions
                $rec['operations'] = $sum.operations
                $rec['globalScope'] = $sum.globalScope
                $rec
            })
    }
    catch {
        # Permissions unreadable: fall back to names only (scoring then uses the built-in name floor).
        $permErr = Get-Short $_.Exception.Message
        try { $out['roles'] = Invoke-RscPaginate $Client $rolesQ 'getAllRolesInOrgConnection' }
        catch { $out['roles'] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
        $out['rolePermissions'] = [ordered]@{ error = $permErr }
    }
    try {
        $groups = Invoke-RscPaginate $Client $groupsQ 'groupsInCurrentAndDescendantOrganization'
        $out['ssoGroups'] = @(foreach ($g in $groups) {
                [ordered]@{
                    groupId    = $g.groupId; groupName = $g.groupName; domainName = $g.domainName
                    roles      = @(foreach ($r in (Get-List $g.roles)) { [ordered]@{ id = $r.id; name = $r.name } })
                    userCount  = (Get-List $g.users).Count
                }
            })
    }
    catch { $out['ssoGroups'] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    return $out
}

function Get-RcClusters($Client) {
    $q = @'
query Clusters($after: String) {
  clusterConnection(after: $after, first: 200) {
    count
    nodes {
      id name version type productType status isHealthy
      encryptionEnabled isAirGapped isTprEnabled isClusterRemovalTprEnabled
      isTunnelEnabled eosStatus eosDate estimatedRunway cyberEventLockdownMode
      lastConnectionTime
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $nodes = Invoke-RscPaginate $Client $q 'clusterConnection'
    $flag = { param($key, $want) @($nodes | Where-Object { Test-Is $_.$key $want }).Count }
    $unknown = { param($key) @($nodes | Where-Object { $null -eq $_.$key }).Count }
    return [ordered]@{
        total                    = $nodes.Count
        connected                = @($nodes | Where-Object { $_.status -eq 'Connected' }).Count
        unhealthy                = & $flag 'isHealthy' $false
        encryptionOff            = & $flag 'encryptionEnabled' $false
        airGapped                = & $flag 'isAirGapped' $true
        # null means RSC did not report it (unknown), which is not the same as off.
        tprOff                   = & $flag 'isTprEnabled' $false
        tprUnknown               = & $unknown 'isTprEnabled'
        clusterRemovalTprOff     = & $flag 'isClusterRemovalTprEnabled' $false
        clusterRemovalTprUnknown = & $unknown 'isClusterRemovalTprEnabled'
        supportTunnelOpen        = & $flag 'isTunnelEnabled' $true
        versions                 = Get-SortedOrdinal ($nodes | ForEach-Object { $_.version } | Where-Object { $_ })
        clusters                 = $nodes
    }
}

function Get-RcThreat($Client) {
    $rootTypes = 'CDM_CLUSTER', 'AWS_NATIVE_ACCOUNT', 'AZURE_NATIVE_SUBSCRIPTION',
    'GCP_NATIVE_PROJECT', 'M365_SUBSCRIPTION', 'CLOUD_DIRECT_CLUSTER'
    # allEnablementItems requires a root object type; query each one separately.
    $enableQ = @'
query Enablement($type: ThreatHuntRootObjectType!) {
  threatAnalyticsEnablement {
    allEnablementItems(type: $type) {
      id name isHealthy threatMonitoringEnabled dataThreatAnalyticsEnabled isYaraProcessingEnabled
    }
  }
}
'@
    $statsQ = @'
query Stats($begin: DateTime!) {
  threatMonitoringObjectEnablementStats(beginTime: $begin) { enabledObjects supportedObjects }
}
'@
    # allEnablementItems(type: CDM_CLUSTER) always returns []. The per-cluster flag is Cluster.lambdaConfig, which is
    # null for a cluster RSC cannot reach. Keep in step with collectors/threat.py cdm_root.
    $cdmQ = @'
query CdmThreat($after: String) {
  clusterConnection(after: $after, first: 200) {
    nodes {
      id name status isHealthy productType
      lambdaConfig {
        isThreatMonitoringEnabled isThreatMonitoringEnabledForActiveDirectory
        isSmartScanningEnabled enableThreatMonitoringFullScan orionYaraRemoteProcessingEnabled
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $out = [ordered]@{ roots = [ordered]@{} }
    foreach ($t in $rootTypes) {
        if ($t -eq 'CDM_CLUSTER') {
            try {
                # Do not pipe Invoke-RscPaginate: it returns the array wrapped, so a pipe sees one item.
                $all = Invoke-RscPaginate $Client $cdmQ 'clusterConnection'
                $nodes = @($all | Where-Object { $_.productType -eq 'CDM' })
                $items = @(); $notAssessed = @()
                foreach ($c in $nodes) {
                    $cfg = $c.lambdaConfig
                    if ($null -eq $cfg) {
                        $notAssessed += [ordered]@{ id = $c.id; name = $c.name; status = $c.status }
                        continue
                    }
                    $items += [ordered]@{
                        id = $c.id; name = $c.name; isHealthy = [bool]$c.isHealthy
                        threatMonitoringEnabled    = [bool]$cfg.isThreatMonitoringEnabled
                        dataThreatAnalyticsEnabled = $false
                        isYaraProcessingEnabled    = [bool]$cfg.orionYaraRemoteProcessingEnabled
                        activeDirectoryEnabled     = [bool]$cfg.isThreatMonitoringEnabledForActiveDirectory
                        smartScanningEnabled       = [bool]$cfg.isSmartScanningEnabled
                        fullScanEnabled            = [bool]$cfg.enableThreatMonitoringFullScan
                    }
                }
                $out.roots[$t] = [ordered]@{
                    total                      = $items.Count
                    threatMonitoringEnabled    = @($items | Where-Object { $_.threatMonitoringEnabled }).Count
                    dataThreatAnalyticsEnabled = 0
                    unhealthy                  = @($items | Where-Object { -not $_.isHealthy }).Count
                    activeDirectoryEnabled     = @($items | Where-Object { $_.activeDirectoryEnabled }).Count
                    smartScanningEnabled       = @($items | Where-Object { $_.smartScanningEnabled }).Count
                    notAssessed                = $notAssessed
                    items                      = $items
                }
            }
            catch { $out.roots[$t] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
            continue
        }
        try {
            $items = @(Get-List (Invoke-RscQuery $Client $enableQ @{ type = $t }).threatAnalyticsEnablement.allEnablementItems)
            $out.roots[$t] = [ordered]@{
                total                      = $items.Count
                threatMonitoringEnabled    = @($items | Where-Object { $_.threatMonitoringEnabled }).Count
                dataThreatAnalyticsEnabled = @($items | Where-Object { $_.dataThreatAnalyticsEnabled }).Count
                unhealthy                  = @($items | Where-Object { -not $_.isHealthy }).Count
                items                      = $items
            }
        }
        catch { $out.roots[$t] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    }
    try {
        $begin = Get-IsoUtc ((Get-Date).AddDays(-30))
        $out['objects'] = (Invoke-RscQuery $Client $statsQ @{ begin = $begin }).threatMonitoringObjectEnablementStats
    }
    catch { $out['objects'] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    return $out
}

function Get-Short([string]$Text) { return $Text.Substring(0, [Math]::Min(300, $Text.Length)) }

# Keep in step with capabilities.HUNT_WINDOW_DAYS.
$script:HuntWindowDays = 90

# threatHunts ignores `first` and a hunt that has not started has a null startTime. So ask for counts only where
# rows are not needed, and take the latest start as the max of the non-null values instead of trusting the order.
function Get-RcHunts($Client, [datetime]$Now = (Get-Date)) {
    $totalQ = 'query { threatHunts { count } }'
    $rowsQ = 'query($begin: DateTime) { threatHunts(beginTime: $begin) { count nodes { startTime } } }'
    $begin = Get-IsoUtc ($Now.AddDays(-$script:HuntWindowDays))
    $total = (Invoke-RscQuery $Client $totalQ).threatHunts.count
    if (-not $total) { return [ordered]@{ total = 0; last90 = 0; latest = $null } }
    $recent = (Invoke-RscQuery $Client $rowsQ @{ begin = $begin }).threatHunts
    $starts = @(Get-List $recent.nodes | ForEach-Object { $_.startTime } | Where-Object { $_ })
    if ($starts.Count) {
        return [ordered]@{ total = $total; last90 = $recent.count; latest = (Get-MaxOrdinal $starts) }
    }
    # Nothing recent. Only now fetch every row, to date the last hunt that did run.
    $all = (Invoke-RscQuery $Client $rowsQ @{ begin = $null }).threatHunts.nodes
    $starts = @(Get-List $all | ForEach-Object { $_.startTime } | Where-Object { $_ })
    $latest = if ($starts.Count) { Get-MaxOrdinal $starts } else { $null }
    return [ordered]@{ total = $total; last90 = 0; latest = $latest }
}

function Get-MaxOrdinal($Strings) {
    $best = $null
    foreach ($s in $Strings) { if ($null -eq $best -or [string]::CompareOrdinal($s, $best) -gt 0) { $best = $s } }
    return $best
}

# The lab returns lastFailedErrorInfo {statusCode: 0} for a webhook with no error, so require a real code or message.
function Test-WebhookFailed($Hook) {
    $e = $Hook.lastFailedErrorInfo
    if ($null -eq $e) { return $false }
    return [bool]$e.errorMessage -or ([int]$e.statusCode -gt 0)
}

function Get-RcWebhookRouting($Client) {
    $q = @'
query {
  allWebhooksV2 {
    status
    subscriptionType {
      eventSubscription {
        isSubscribedToAllEvents eventTypes severities
        templateInfo { templateId customTemplate }
      }
    }
  }
}
'@
    $tplQ = 'query($t: TemplateRecordType!) { allWebhookMessageTemplates(input: {recordType: $t}) { id msgType templateData } }'
    $hooks = Get-List (Invoke-RscQuery $Client $q).allWebhooksV2
    $templates = @{}
    foreach ($kind in 'DEFAULT', 'CUSTOM') {
        try {
            foreach ($t in (Get-List (Invoke-RscQuery $Client $tplQ @{ t = $kind }).allWebhookMessageTemplates)) {
                $templates[[string]$t.id] = if ($t.templateData) { [string]$t.templateData } else { '' }
            }
        }
        catch { }  # templates unreadable: webhooks that point at them are counted as unknown below
    }
    $event = @()
    foreach ($h in $hooks) {
        if ((Get-Str $h.status).ToUpper() -ne 'ENABLED') { continue }
        $es = $h.subscriptionType.eventSubscription
        if ($null -ne $es -and ($es.isSubscribedToAllEvents -or (Test-Any $es.eventTypes))) { $event += , $es }
    }
    $out = [ordered]@{ eventWebhooks = $event.Count; criticalOnly = 0; templateChecked = 0; withoutEventInfo = 0
        templateUnknown = 0
    }
    foreach ($es in $event) {
        $sev = @(Get-List $es.severities)
        if ($sev.Count -and @($sev | Select-Object -Unique).Count -eq 1 -and $sev[0] -eq 'SEVERITY_CRITICAL') {
            $out.criticalOnly++
        }
        $ti = $es.templateInfo
        $text = $null
        if ($ti -and $ti.customTemplate) { $text = [string]$ti.customTemplate }
        elseif ($ti -and $null -ne $ti.templateId) { $text = $templates[[string]$ti.templateId] }
        if ($null -eq $text) { $out.templateUnknown++; continue }
        $out.templateChecked++
        if (-not $text.ToLower().Contains('eventinfo')) { $out.withoutEventInfo++ }
    }
    return $out
}

function Get-RcEmail($Client) {
    $q = @'
query Email($after: String) {
  usersInCurrentAndDescendantOrganization(after: $after, first: 200) {
    count
    nodes { isEmailEnabled emailConfig { digestId } }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $users = Invoke-RscPaginate $Client $q 'usersInCurrentAndDescendantOrganization'
    return [ordered]@{
        users        = $users.Count
        emailEnabled = @($users | Where-Object { Test-Is $_.isEmailEnabled $true }).Count
        # emailConfig is a list on a real tenant: an empty list means no digest, so test for content, not null.
        withDigest   = @($users | Where-Object { Test-Any $_.emailConfig }).Count
    }
}

function Get-RcCdmNotifications($Client) {
    $cdmQ = @'
query Cdm($after: String) {
  clusterConnection(after: $after, first: 200) { nodes { id productType status } pageInfo { hasNextPage endCursor } }
}
'@
    $syslogQ = 'query($c: String!) { syslogExportRules(input: {clusterUuid: $c}) { total } }'
    # communityString is a credential, so it is never requested. Only whether SNMP and trap receivers exist.
    $snmpQ = 'query($c: String!) { snmpConfigurations(input: {clusterUuid: $c, id: "me"}) { isEnabled trapReceiverConfigs { port } } }'
    $nodes = Invoke-RscPaginate $Client $cdmQ 'clusterConnection'
    $cdm = @($nodes | Where-Object { $_.productType -eq 'CDM' -and $_.status -eq 'Connected' })
    $out = [ordered]@{ cdmClusters = $cdm.Count; checked = 0; unreadable = 0; noSyslog = 0; noTrapReceiver = 0; neither = 0 }
    foreach ($c in $cdm) {
        try {
            $syslog = [int](Invoke-RscQuery $Client $syslogQ @{ c = $c.id }).syslogExportRules.total
            $snmp = (Invoke-RscQuery $Client $snmpQ @{ c = $c.id }).snmpConfigurations
            $traps = if ($snmp.isEnabled) { (Get-List $snmp.trapReceiverConfigs).Count } else { 0 }
        }
        catch { $out.unreadable++; continue }
        $out.checked++
        if ($syslog -eq 0) { $out.noSyslog++ }
        if ($traps -eq 0) { $out.noTrapReceiver++ }
        if ($syslog -eq 0 -and $traps -eq 0) { $out.neither++ }
    }
    return $out
}

function Get-RcDetection($Client) {
    $settingsQ = 'query { lambdaSettings { anomalyThreshold ransomwareThreshold isAnomalyAlertEnabled } }'
    $hooksQ = @'
query {
  allWebhooksV2 {
    id name status providerType
    lastFailedErrorInfo { statusCode errorMessage }
    subscriptionType {
      auditSubscription { isSubscribedToAllAudits auditTypes }
      eventSubscription { isSubscribedToAllEvents eventTypes }
    }
  }
}
'@
    $out = [ordered]@{}
    try { $out['settings'] = (Invoke-RscQuery $Client $settingsQ).lambdaSettings }
    catch { $out['settings'] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    try { $out['hunts'] = Get-RcHunts $Client }
    catch { $out['hunts'] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    try {
        $hooks = @(Get-List (Invoke-RscQuery $Client $hooksQ).allWebhooksV2)
        $enabled = @($hooks | Where-Object { (Get-Str $_.status).ToUpper() -eq 'ENABLED' })
        # A subscription object can exist and still select nothing, so look at what it subscribes to.
        $feeds = {
            param($h, $key, $allFlag, $typesKey)
            $s = $h.subscriptionType.$key
            [bool]($null -ne $s -and ($s.$allFlag -or (Test-Any $s.$typesKey)))
        }
        $out['webhooks'] = [ordered]@{
            total         = $hooks.Count
            enabled       = $enabled.Count
            withAuditFeed = @($enabled | Where-Object { & $feeds $_ 'auditSubscription' 'isSubscribedToAllAudits' 'auditTypes' }).Count
            withEventFeed = @($enabled | Where-Object { & $feeds $_ 'eventSubscription' 'isSubscribedToAllEvents' 'eventTypes' }).Count
            failing       = @($enabled | Where-Object { Test-WebhookFailed $_ }).Count
        }
    }
    catch { $out['webhooks'] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    # Each block below is isolated: a denied field here must never take down the sections above.
    # Only aggregates are stored. Names, URLs, recipients and hostnames never enter the bundle.
    $blocks = [ordered]@{
        webhookRouting   = { Get-RcWebhookRouting $Client }
        email            = { Get-RcEmail $Client }
        cdmNotifications = { Get-RcCdmNotifications $Client }
    }
    foreach ($key in $blocks.Keys) {
        try { $out[$key] = & $blocks[$key] }
        catch { $out[$key] = [ordered]@{ error = (Get-Short $_.Exception.Message) } }
    }
    return $out
}

function Get-RcDhrc($Client) {
    $q = @'
query Dhrc {
  allDhrcScores(timespan: WEEK) {
    category value calculatedAt date earliestMetric
    context { metrics { metric value maxValue weight impact version } }
  }
}
'@
    $rows = @(Get-List (Invoke-RscQuery $Client $q).allDhrcScores)
    $latest = [ordered]@{}
    foreach ($r in $rows) {
        $cur = $latest[[string]$r.category]
        if ($null -eq $cur -or [string]::CompareOrdinal((Get-Str $r.date), (Get-Str $cur.date)) -gt 0) {
            $latest[[string]$r.category] = $r
        }
    }
    $scores = [ordered]@{}
    foreach ($cat in $latest.Keys) {
        $r = $latest[$cat]
        $scores[$cat] = [ordered]@{
            value   = [Math]::Round([double]$r.value, 1)
            date    = $r.date
            metrics = @(foreach ($m in (Get-List $r.context.metrics)) {
                    [ordered]@{ metric = $m.metric; value = $m.value; maxValue = $m.maxValue; weight = $m.weight; impact = $m.impact }
                })
        }
    }
    return [ordered]@{
        scores  = $scores
        history = @(foreach ($r in $rows) {
                [ordered]@{ category = $r.category; date = $r.date; value = [Math]::Round([double]$r.value, 1) }
            })
    }
}

function Get-RcRecovery($Client) {
    $q = @'
query Plans($after: String) {
  recoveryPlansBasicInfo(after: $after, first: 100) {
    count
    nodes {
      id name isArchived recoveryPlanStatus recoveryPlanType workloadType numChildren
      latestRecovery { endTime recoveryOutcome isAdhocRecovery }
      recoverySchedule { nextRunTime }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $nodes = Invoke-RscPaginate $Client $q 'recoveryPlansBasicInfo'
    $plans = @($nodes | Where-Object { -not $_.isArchived })
    $ran = @($plans | Where-Object { $_.latestRecovery })
    return [ordered]@{
        total          = $plans.Count
        configured     = @($plans | Where-Object { $_.recoveryPlanStatus -eq 'CONFIGURED' }).Count
        neverRun       = @($plans | Where-Object { -not $_.latestRecovery }).Count
        lastRunFailed  = @($ran | Where-Object { $_.latestRecovery.recoveryOutcome -eq 'FAILED' }).Count
        scheduled      = @($plans | Where-Object { $_.recoverySchedule.nextRunTime }).Count
        cyberRecovery  = @($plans | Where-Object { $_.recoveryPlanType -eq 'CYBER_RECOVERY' }).Count
        plans          = $plans
    }
}

function Get-RcOffsite($Client) {
    $q = @'
query Offsite($after: String) {
  slaDomains(after: $after, first: 200, shouldShowProtectedObjectCount: true) {
    count
    nodes {
      id name
      ... on GlobalSlaReply {
        protectedObjectCount isArchived
        baseFrequency { duration unit }
        archivalSpecs {
          isComplianceImmutabilityEnabled
          archivalLocationToClusterMapping { location { name targetType } }
        }
        replicationSpecsV2 { cluster { name } targetMapping { targetType } }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $slas = Invoke-RscPaginate $Client $q 'slaDomains'
    # Pseudo-SLAs (unprotected, do not protect) carry no protectedObjectCount field.
    $real = @($slas | Where-Object { (Test-Prop $_ 'protectedObjectCount') -and -not $_.isArchived })
    # True / False only when RSC returned the spec list; $null means unknown and is never a gap.
    $flag = { param($specs) if ($null -eq $specs) { $null } else { [bool](Test-Any $specs) } }
    $per = New-Object System.Collections.Generic.List[object]
    $fallback = 0
    $countQ = 'query($f: SnappableFilterInput){snappableConnection(first:1, filter:$f){count}}'
    foreach ($s in $real) {
        $records = $s.protectedObjectCount
        if (-not $records) { continue }
        # Active, protected objects only. protectedObjectCount also counts relic and archived records.
        try {
            $f = @{ slaDomain = @{ id = @([string]$s.id) }; objectState = @('ACTIVE'); protectionStatus = @('Protected') }
            $n = (Invoke-RscQuery $Client $countQ @{ f = $f }).snappableConnection.count
        }
        catch { $n = $records; $fallback++ }
        if (-not $n) { continue }
        $archive = @(foreach ($a in (Get-List $s.archivalSpecs)) {
                foreach ($m in (Get-List $a.archivalLocationToClusterMapping)) {
                    [ordered]@{ name = $m.location.name; type = $m.location.targetType
                        immutable = [bool]$a.isComplianceImmutabilityEnabled
                    }
                }
            })
        $repl = @(foreach ($r in (Get-List $s.replicationSpecsV2)) {
                [ordered]@{ cluster = $r.cluster.name; type = $r.targetMapping.targetType }
            })
        $per.Add([ordered]@{
                name = $s.name; objects = $n; recordCount = $records
                replication = (& $flag $s.replicationSpecsV2); archival = (& $flag $s.archivalSpecs)
                replicationTargets = $repl; archiveTargets = $archive; frequency = $s.baseFrequency
            })
    }
    $objs = { param($pred) Get-Sum ($per | Where-Object { & $pred $_ } | ForEach-Object { $_['objects'] }) }
    return [ordered]@{
        basis                   = 'active-protected'
        fallbackSlas            = $fallback
        recordCount             = Get-Sum ($per | ForEach-Object { $_['recordCount'] })
        slasInUse               = $per.Count
        objects                 = & $objs { $true }
        objectsReplicationKnown = & $objs { param($p) $null -ne $p['replication'] }
        objectsArchivalKnown    = & $objs { param($p) $null -ne $p['archival'] }
        objectsBothKnown        = & $objs { param($p) $null -ne $p['replication'] -and $null -ne $p['archival'] }
        noReplication           = & $objs { param($p) Test-Is $p['replication'] $false }
        noArchival              = & $objs { param($p) Test-Is $p['archival'] $false }
        singleCopy              = & $objs { param($p) (Test-Is $p['replication'] $false) -and (Test-Is $p['archival'] $false) }
        withReplication         = & $objs { param($p) Test-Is $p['replication'] $true }
        withArchival            = & $objs { param($p) Test-Is $p['archival'] $true }
        slas                    = $per.ToArray()
    }
}

# Name/location tokens that suggest non-production. Heuristic only; the report labels it as such.
$script:NonProdRe = [regex]::new('(?<![a-z])(dev|test|tst|qa|uat|stg|stage|staging|sandbox|lab|poc|demo)(?![a-z])',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase)
# Folder names that are structural, never evidence of environment.
$script:StructuralFolders = @('vm', 'templates', 'datacenters', 'datacenter')
$script:UnprotectedSlaIds = @('UNPROTECTED', 'DO_NOT_PROTECT')

function Get-VmSignals($Vm) {
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Get-List $Vm.logicalPath)) {
        if ($p.objectType -eq 'VSphereFolder' -and $script:StructuralFolders -notcontains ([string]$p.name).ToLower()) {
            if ($script:NonProdRe.IsMatch([string]$p.name)) { $hits.Add(@('folder', [string]$p.name)) }
        }
    }
    foreach ($p in (Get-List $Vm.vsphereTagPath)) {
        if (@('VSphereTag', 'VSphereTagCategory') -contains $p.objectType -and $script:NonProdRe.IsMatch([string]$p.name)) {
            $hits.Add(@('vsphereTag', [string]$p.name))
        }
    }
    foreach ($t in (Get-List $Vm.allTags)) {
        if ($script:NonProdRe.IsMatch("$($t.key) $($t.value)")) {
            $hits.Add(@('rscTag', "$($t.key)=$($t.value)".Trim('=')))
        }
    }
    if ($script:NonProdRe.IsMatch([string]$Vm.name)) { $hits.Add(@('vmName', [string]$Vm.name)) }
    return , $hits.ToArray()
}

function Get-VmEnvironment($Client) {
    # 100 per page, not 500: Windows PowerShell 5.1 ConvertFrom-Json fails on responses over 2 MB.
    $q = @'
query Vms($after: String) {
  vSphereVmNewConnection(after: $after, first: 100) {
    count
    nodes {
      name isRelic templateType
      effectiveSlaDomain { id name }
      logicalPath { name objectType }
      vsphereTagPath { name objectType }
      allTags { key value }
      cluster { name }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $pages = Invoke-RscPaginate $Client $q 'vSphereVmNewConnection'
    $all = @($pages | Where-Object { -not $_.isRelic })
    $templates = @($all | Where-Object { $_.templateType -ne 'VM' })
    $entries = @($all | Where-Object { $_.templateType -eq 'VM' })

    # The same VM appears once per cluster that sees its vCenter, each with its own SLA.
    # Collapse to one record per (vCenter, folder path, name); protected if ANY cluster protects it.
    $groups = [ordered]@{}
    foreach ($v in $entries) {
        $vcenter = '?'
        foreach ($p in (Get-List $v.logicalPath)) { if ($p.objectType -eq 'VSphereVCenter') { $vcenter = $p.name; break } }
        $folders = @(Get-List $v.logicalPath | Where-Object { $_.objectType -eq 'VSphereFolder' } | ForEach-Object { $_.name })
        $key = (@($vcenter) + $folders + @($v.name)) -join [char]1
        if (-not $groups.Contains($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object] }
        $groups[$key].Add($v)
    }
    $vms = New-Object System.Collections.Generic.List[object]
    foreach ($key in $groups.Keys) {
        $grp = $groups[$key]
        $first = $grp[0]
        $prot = @($grp | Where-Object { $script:UnprotectedSlaIds -notcontains $_.effectiveSlaDomain.id })
        $vms.Add([pscustomobject]@{
                name = $first.name; cluster = $first.cluster.name
                protected = ($prot.Count -gt 0); clusterEntries = $grp.Count; clustersProtecting = $prot.Count
                signals = (Get-VmSignals $first)
            })
    }
    $nonprod = @($vms | Where-Object { $_.signals.Count -gt 0 })
    $prodlike = @($vms | Where-Object { $_.signals.Count -eq 0 })
    $folderOnly = @($nonprod | Where-Object { @($_.signals | Where-Object { @('folder', 'vsphereTag', 'rscTag') -contains $_[0] }).Count })
    $slaTop = Get-Tally ($entries | ForEach-Object { $_.effectiveSlaDomain.id }) -Top 8
    $matched = Get-Tally ($nonprod | ForEach-Object { $_.signals | ForEach-Object { $_[1] } }) -Top 30
    return [ordered]@{
        activeVmEntries    = $entries.Count
        templatesExcluded  = $templates.Count
        activeVms          = $vms.Count
        partiallyProtected = @($vms | Where-Object { 0 -lt $_.clustersProtecting -and $_.clustersProtecting -lt $_.clusterEntries }).Count
        slaIdCounts        = $slaTop
        slaIdNote          = '00000000-0000-0000-0000-000000000002 is the built-in Bronze SLA (protected).'
        nonProd            = [ordered]@{
            total = $nonprod.Count
            protected = @($nonprod | Where-Object { $_.protected }).Count
            unprotected = @($nonprod | Where-Object { -not $_.protected }).Count
            structuralSignalTotal = $folderOnly.Count
        }
        prodLike           = [ordered]@{
            total = $prodlike.Count
            protected = @($prodlike | Where-Object { $_.protected }).Count
            unprotected = @($prodlike | Where-Object { -not $_.protected }).Count
        }
        signalSources      = Get-Tally ($nonprod | ForEach-Object { @($_.signals | ForEach-Object { $_[0] } | Select-Object -Unique) })
        matchedText        = $matched
        unprotectedNonProd = @(foreach ($v in ($nonprod | Where-Object { -not $_.protected })) {
                [ordered]@{ name = $v.name; cluster = $v.cluster; signals = $v.signals }
            })
    }
}

function Get-BackupHealth($Client) {
    # Mirrors collectors/inventory.py _backup_health. Explicit window: the default is the whole protection lifetime.
    $q = 'query($f: SnappableFilterInput){snappableConnection(first:1, filter:$f){count}}'
    $n = {
        param($status)
        $f = @{ objectState = @('ACTIVE'); protectionStatus = @('Protected'); slaTimeRange = 'PAST_7_DAYS'
            complianceStatus = @($status)
        }
        (Invoke-RscQuery $Client $q @{ f = $f }).snappableConnection.count
    }
    return [ordered]@{
        window          = 'PAST_7_DAYS'
        inCompliance    = & $n 'IN_COMPLIANCE'
        outOfCompliance = & $n 'OUT_OF_COMPLIANCE'
        notAvailable    = & $n 'NOT_AVAILABLE'
        empty           = & $n 'EMPTY'
    }
}

function Get-Reconciliation($Client, $Summary) {
    $q = 'query($f: SnappableFilterInput){snappableConnection(first:1, filter:$f){count}}'
    $n = { param($f) (Invoke-RscQuery $Client $q @{ f = $f }).snappableConnection.count }
    $active = @{ objectState = @('ACTIVE') }
    return [ordered]@{
        snappables      = [ordered]@{
            active             = & $n $active
            relic              = & $n @{ objectState = @('RELIC') }
            archived           = & $n @{ objectState = @('ARCHIVED') }
            activeProtected    = & $n @{ objectState = @('ACTIVE'); protectionStatus = @('Protected') }
            activeNoSla        = & $n @{ objectState = @('ACTIVE'); protectionStatus = @('NoSla') }
            activeDoNotProtect = & $n @{ objectState = @('ACTIVE'); protectionStatus = @('DoNotProtect') }
        }
        coverageSummary = [ordered]@{
            supported = $Summary.overallProtectionCoverage.supportedObjectsCount
            protected = $Summary.overallProtectionCoverage.protectedObjectsCount
        }
        note            = 'Counts are object records, not distinct workloads. Do not dedupe by name: Azure DevOps ' +
        'repos repeat a name across projects (verified: same name, different project and URL, ' +
        'each a separate repository), and the row location shows only the organization. A few ' +
        'objects (VMs, databases, domain controllers) appear once per replicating cluster under ' +
        'the same id, so the unprotected list is deduped by id and VM statements use ' +
        'vmEnvironment. The RSC cockpit PROTECTED_OBJECTS metric (see dhrc) is close to ' +
        'active plus protected-relic objects but is computed daily and does not match exactly. ' +
        'dataProtectionCoverageSummary uses a different, smaller object universe that we could ' +
        'not reproduce from snappable data. Reports quote object records and cite the cockpit ' +
        'figure alongside.'
    }
}

function Get-RcInventory($Client) {
    $coverageQ = @'
query Coverage($days: Int!) {
  dataProtectionCoverageSummary(historicalDeltaDays: $days) {
    overallProtectionCoverage {
      platformCategory protectedObjectsCount supportedObjectsCount
      protectionPercentCoverage violatedSensitiveObjects
    }
    platformCoverage {
      platformCategory protectedObjectsCount supportedObjectsCount
      protectionPercentCoverage violatedSensitiveObjects
    }
  }
}
'@
    $unprotQ = @'
query Unprotected($after: String) {
  snappableConnection(
    after: $after
    first: 500
    filter: {protectionStatus: [NoSla, DoNotProtect], objectState: [ACTIVE]}
  ) {
    count
    nodes {
      id name objectType location protectionStatus complianceStatus
      logicalBytes cluster { id name }
    }
    pageInfo { hasNextPage endCursor }
  }
}
'@
    $s = (Invoke-RscQuery $Client $coverageQ @{ days = 30 }).dataProtectionCoverageSummary
    $cover = @(Get-List $s.platformCoverage)
    if ($s.overallProtectionCoverage) { $cover += $s.overallProtectionCoverage }
    foreach ($p in $cover) {
        Set-Prop $p 'unprotectedObjectsCount' ($p.supportedObjectsCount - $p.protectedObjectsCount)
    }

    # The same object is listed once per replicating cluster: keep the first row per id.
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Invoke-RscPaginate $Client $unprotQ 'snappableConnection')) {
        if (-not $seen.Add([string]$r.id)) { continue }
        $cluster = if ($r.cluster -and $r.cluster.name) { $r.cluster.name } else { 'unknown' }
        $row = [ordered]@{}
        foreach ($n in (Get-PropNames $r)) { if ($n -ne 'cluster') { $row[$n] = $r.$n } }
        $row['clusterName'] = $cluster
        $row['likelyNonProd'] = $script:NonProdRe.IsMatch("$($r.name) $($r.location)")
        $rows.Add($row)
    }
    $nonprod = @($rows | Where-Object { $_['likelyNonProd'] })
    $loc = { param($r) $first = ([string]$r['location']).Split('/')[0]; if ($first) { $first } else { 'unknown' } }
    Set-Prop $s 'unprotected' ([ordered]@{
            total         = $rows.Count
            noSla         = @($rows | Where-Object { $_['protectionStatus'] -eq 'NoSla' }).Count
            doNotProtect  = @($rows | Where-Object { $_['protectionStatus'] -eq 'DoNotProtect' }).Count
            likelyNonProd = $nonprod.Count
            logicalBytes  = Get-Sum ($rows | ForEach-Object { $_['logicalBytes'] })
            byType        = Get-Tally ($rows | ForEach-Object { $_['objectType'] })
            byCluster     = Get-Tally ($rows | ForEach-Object { $_['clusterName'] })
            byLocation    = Get-Tally ($rows | ForEach-Object { & $loc $_ }) -Top 25
            nonProdByType = Get-Tally ($nonprod | ForEach-Object { $_['objectType'] })
            rows          = $rows.ToArray()
        })
    Set-Prop $s 'vmEnvironment' (Get-VmEnvironment $Client)
    Set-Prop $s 'backupHealth' (Get-BackupHealth $Client)
    Set-Prop $s 'reconciliation' (Get-Reconciliation $Client $s)
    return $s
}

$script:Collectors = [ordered]@{
    identity  = { param($c) Get-RcIdentity $c }
    mfa       = { param($c) Get-RcMfa $c }
    quorum    = { param($c) Get-RcQuorum $c }
    inventory = { param($c) Get-RcInventory $c }
    dhrc      = { param($c) Get-RcDhrc $c }
    sla       = { param($c) Get-RcSla $c }
    access    = { param($c) Get-RcAccess $c }
    clusters  = { param($c) Get-RcClusters $c }
    threat    = { param($c) Get-RcThreat $c }
    detection = { param($c) Get-RcDetection $c }
    recovery  = { param($c) Get-RcRecovery $c }
    offsite   = { param($c) Get-RcOffsite $c }
}

# ---------------------------------------------------------------------------------------------------------------
# Redaction (port of redact.py). Pseudonyms are <kind>-<8 hex> from a random per-run salt. The bundle is changed in
# place: the raw bundle is written to disk before this runs.
# ---------------------------------------------------------------------------------------------------------------

$script:BuiltinRoles = @('Administrator', 'Owner', 'Read-only Administrator', 'QAuth Admin', 'QAuth Approver')
$script:EmailRe = [regex]"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

function New-Pseudonymizer {
    $saltBytes = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($saltBytes); $rng.Dispose()
    return @{
        Salt = ([BitConverter]::ToString($saltBytes) -replace '-', '').ToLower()
        Map  = [ordered]@{}
        Sha  = [Security.Cryptography.SHA256]::Create()
    }
}

function Get-Pseudonym($Ps, [string]$Kind, $Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $Value }
    $key = "${Kind}:$Value"
    if (-not $Ps.Map.Contains($key)) {
        $hash = $Ps.Sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$($Ps.Salt)|$key"))
        $hex = ([BitConverter]::ToString($hash) -replace '-', '').ToLower().Substring(0, 8)
        $Ps.Map[$key] = "$Kind-$hex"
    }
    return $Ps.Map[$key]
}

function Protect-Role($Ps, $Role) {
    if (-not (Test-IsMap $Role)) { return }
    if ((Test-Prop $Role 'name') -and $script:BuiltinRoles -notcontains (Get-Prop $Role 'name')) {
        Set-Prop $Role 'name' (Get-Pseudonym $Ps 'role' (Get-Prop $Role 'name'))
    }
    if (Get-Prop $Role 'description') { Set-Prop $Role 'description' 'withheld by redaction' }
    if (Test-Prop $Role 'id') { Set-Prop $Role 'id' (Get-Pseudonym $Ps 'role' (Get-Prop $Role 'id')) }
}

function Protect-Field($Ps, $Obj, [string]$Name, [string]$Kind) {
    Set-Prop $Obj $Name (Get-Pseudonym $Ps $Kind (Get-Prop $Obj $Name))
}

function Hide-ErrorText($Node) {
    if ($Node -is [System.Array]) { foreach ($v in $Node) { Hide-ErrorText $v }; return }
    if (-not (Test-IsMap $Node)) { return }
    if (Test-Prop $Node 'error') { Set-Prop $Node 'error' 'withheld by redaction' }
    foreach ($n in (Get-PropNames $Node)) { Hide-ErrorText (Get-Prop $Node $n) }
}

function Protect-Bundle($Bundle) {
    $ps = New-Pseudonymizer
    $d = $Bundle.data
    $sect = { param($name) $v = Get-Prop $d $name; if ($null -eq $v) { [ordered]@{} } else { $v } }

    # Identity
    foreach ($u in (Get-List (Get-Prop (& $sect 'identity') 'users'))) {
        Protect-Field $ps $u 'id' 'user'
        Protect-Field $ps $u 'email' 'email'
        if (Test-Prop $u 'username') { Protect-Field $ps $u 'username' 'user' }
        foreach ($r in (Get-List (Get-Prop $u 'roles'))) { Protect-Role $ps $r }
    }

    # Access
    $a = & $sect 'access'
    $svc = Get-Prop $a 'serviceAccounts'
    if ($svc -is [System.Array]) {
        foreach ($s in $svc) {
            Protect-Field $ps $s 'name' 'svc'
            Protect-Field $ps $s 'clientId' 'client'
            foreach ($r in (Get-List (Get-Prop $s 'roles'))) { Protect-Role $ps $r }
        }
    }
    if ((Get-Prop $a 'roles') -is [System.Array]) { foreach ($r in (Get-Prop $a 'roles')) { Protect-Role $ps $r } }
    if ((Get-Prop $a 'ssoGroups') -is [System.Array]) {
        foreach ($g in (Get-Prop $a 'ssoGroups')) {
            Protect-Field $ps $g 'groupId' 'group'
            Protect-Field $ps $g 'groupName' 'group'
            Protect-Field $ps $g 'domainName' 'idp'
            foreach ($r in (Get-List (Get-Prop $g 'roles'))) { Protect-Role $ps $r }
        }
    }
    $ip = Get-Prop $a 'ipAllowlist'
    if ((Test-IsMap $ip) -and (Get-Prop $ip 'ipCidrs') -is [System.Array]) {
        Set-Prop $ip 'ipCidrs' @(foreach ($c in (Get-Prop $ip 'ipCidrs')) { Get-Pseudonym $ps 'ip' $c })
    }
    if ((Get-Prop $a 'identityProviders') -is [System.Array]) {
        foreach ($p in (Get-Prop $a 'identityProviders')) { Protect-Field $ps $p 'name' 'idp' }
    }

    # Quorum
    $q = & $sect 'quorum'
    $orgs = Get-Prop $q 'orgs'
    if (Test-IsMap $orgs) {
        $new = [ordered]@{}
        foreach ($k in (Get-PropNames $orgs)) { $new[(Get-Pseudonym $ps 'org' $k)] = Get-Pseudonym $ps 'org' (Get-Prop $orgs $k) }
        Set-Prop $q 'orgs' $new
    }
    $cfg = Get-Prop $q 'config'
    if (Test-IsMap $cfg) {
        $new = [ordered]@{}
        foreach ($k in (Get-PropNames $cfg)) { $new[(Get-Pseudonym $ps 'org' $k)] = Get-Prop $cfg $k }
        Set-Prop $q 'config' $new
    }
    foreach ($p in (Get-List (Get-Prop $q 'policies'))) {
        Protect-Field $ps $p 'policyId' 'policy'
        Protect-Field $ps $p 'policyName' 'policy'
        Protect-Field $ps $p 'orgId' 'org'
        Protect-Field $ps $p 'orgName' 'org'
    }

    # SLAs: names identify business units
    foreach ($s in (Get-List (Get-Prop (& $sect 'sla') 'slas'))) {
        Protect-Field $ps $s 'id' 'sla'
        Protect-Field $ps $s 'name' 'sla'
    }

    # Offsite: SLA, archive location and replication cluster names. Scoring reads only the counts.
    foreach ($s in (Get-List (Get-Prop (& $sect 'offsite') 'slas'))) {
        Protect-Field $ps $s 'name' 'sla'
        foreach ($t in (Get-List (Get-Prop $s 'archiveTargets'))) { Protect-Field $ps $t 'name' 'archive' }
        foreach ($t in (Get-List (Get-Prop $s 'replicationTargets'))) { Protect-Field $ps $t 'cluster' 'cluster' }
    }

    # Recovery plans: names identify applications and business units.
    foreach ($p in (Get-List (Get-Prop (& $sect 'recovery') 'plans'))) { Protect-Field $ps $p 'name' 'plan' }

    # Clusters
    foreach ($c in (Get-List (Get-Prop (& $sect 'clusters') 'clusters'))) {
        Protect-Field $ps $c 'id' 'cluster'
        Protect-Field $ps $c 'name' 'cluster'
    }

    # Inventory
    $inv = & $sect 'inventory'
    $un = Get-Prop $inv 'unprotected'; if ($null -eq $un) { $un = [ordered]@{} }
    foreach ($r in (Get-List (Get-Prop $un 'rows'))) {
        Protect-Field $ps $r 'id' 'obj'
        Protect-Field $ps $r 'name' 'obj'
        Protect-Field $ps $r 'location' 'loc'
        Protect-Field $ps $r 'clusterName' 'cluster'
    }
    foreach ($pair in @(@('byCluster', 'cluster'), @('byLocation', 'loc'))) {
        foreach ($t in (Get-List (Get-Prop $un $pair[0]))) { Protect-Field $ps $t 'key' $pair[1] }
    }
    $env = Get-Prop $inv 'vmEnvironment'; if ($null -eq $env) { $env = [ordered]@{} }
    foreach ($t in (Get-List (Get-Prop $env 'matchedText'))) { Protect-Field $ps $t 'key' 'obj' }
    foreach ($v in (Get-List (Get-Prop $env 'unprotectedNonProd'))) {
        Protect-Field $ps $v 'name' 'obj'
        Protect-Field $ps $v 'cluster' 'cluster'
        $pairs = New-Object System.Collections.Generic.List[object]
        foreach ($sig in (Get-Prop $v 'signals')) { $pairs.Add(@($sig[0], (Get-Pseudonym $ps 'obj' $sig[1]))) }
        Set-Prop $v 'signals' $pairs.ToArray()
    }

    # Threat monitoring roots (cloud account / subscription names and ids)
    $roots = Get-Prop (& $sect 'threat') 'roots'
    if (Test-IsMap $roots) {
        foreach ($rn in (Get-PropNames $roots)) {
            $root = Get-Prop $roots $rn
            if (-not (Test-IsMap $root)) { continue }
            foreach ($i in (Get-List (Get-Prop $root 'items'))) {
                Protect-Field $ps $i 'id' 'acct'
                Protect-Field $ps $i 'name' 'acct'
            }
        }
    }

    # Alerting. Drop raw webhook records from bundles collected by older versions; no rule reads them.
    $wh = Get-Prop (& $sect 'detection') 'webhooks'
    if (Test-IsMap $wh) { Remove-Prop $wh 'items' }

    # Error stubs can echo ids or hostnames from the API; keep the shape, drop the text.
    foreach ($name in (Get-PropNames $Bundle.status)) {
        if ((Get-Prop $Bundle.status $name) -ne 'ok') { Set-Prop $Bundle.status $name 'error (detail withheld by redaction)' }
    }
    Hide-ErrorText $d
    Set-Prop $Bundle 'redacted' $true

    # Last line of defense: any email still present anywhere is pseudonymized. Done on the serialized text so the
    # bundle is never re-parsed (Windows PowerShell 5.1 cannot parse JSON over 2 MB).
    $text = ConvertTo-BundleJson $Bundle
    $text = $script:EmailRe.Replace($text, [Text.RegularExpressions.MatchEvaluator] { param($m) Get-Pseudonym $ps 'email' $m.Value })
    return [pscustomobject]@{
        Json = (Remove-DateMark $text)
        Map  = [ordered]@{ salt_note = 'keep this file; it reverses the pseudonyms'; map = $ps.Map }
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Preflight and main
# ---------------------------------------------------------------------------------------------------------------

function Get-Failures($Node, [string]$Path = '') {
    if (-not (Test-IsMap $Node)) { return }
    if (Test-Prop $Node 'error') {
        [pscustomobject]@{ Path = $(if ($Path) { $Path } else { '(root)' }); Message = [string](Get-Prop $Node 'error') }
        return
    }
    foreach ($n in (Get-PropNames $Node)) {
        Get-Failures (Get-Prop $Node $n) $(if ($Path) { "$Path.$n" } else { $n })
    }
}

function Invoke-Preflight($Client) {
    Write-Host "authenticated to $($Client.GqlUrl.Split('/api')[0])"
    $bad = 0
    foreach ($name in $script:Collectors.Keys) {
        try { $data = & $script:Collectors[$name] $Client }
        catch {
            $bad++
            Write-Host ("FAIL  {0}: {1}" -f $name, (Get-Str $_.Exception.Message).Substring(0, [Math]::Min(140, (Get-Str $_.Exception.Message).Length)))
            continue
        }
        $sub = @(Get-Failures $data)
        if ($sub.Count) {
            $bad += $sub.Count
            foreach ($f in $sub) { Write-Host ("FAIL  {0}.{1}: {2}" -f $name, $f.Path, $f.Message.Substring(0, [Math]::Min(140, $f.Message.Length))) }
        }
        else { Write-Host "ok    $name" }
    }
    if ($bad) {
        Write-Host "$bad problem(s): grant the missing view permissions or expect those areas to be reported as not assessed"
    }
    else { Write-Host 'all collectors can read' }
    return $(if ($bad) { 1 } else { 0 })
}

function Invoke-Collect($Client, [string]$Customer, [string]$OutDir, [bool]$DoRedact) {
    $bundle = [ordered]@{
        customer     = $Customer
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
        status       = [ordered]@{}
        data         = [ordered]@{}
    }
    foreach ($name in $script:Collectors.Keys) {
        try {
            $bundle.data[$name] = & $script:Collectors[$name] $Client
            $bundle.status[$name] = 'ok'
        }
        catch { $bundle.status[$name] = 'error: ' + (Get-Short (Get-Str $_.Exception.Message)) }  # record and continue
        Write-Host "${name}: $($bundle.status[$name])"
    }
    $dir = Join-Path (Resolve-UserPath $OutDir) $Customer
    [void](New-Item -ItemType Directory -Force -Path $dir)
    $path = Join-Path $dir 'bundle.json'
    Write-Utf8 $path (Remove-DateMark (ConvertTo-BundleJson $bundle))
    Write-Host "wrote $path"
    if ($DoRedact) {
        $red = Protect-Bundle $bundle
        $rp = Join-Path $dir 'bundle.redacted.json'
        $mp = Join-Path $dir 'redaction-map.json'
        Write-Utf8 $rp $red.Json
        Write-Utf8 $mp (ConvertTo-Json -InputObject $red.Map -Depth 10)
        Write-Host "wrote $rp (send this one)"
        Write-Host "wrote $mp (keep this one, do not send)"
    }
}

# Dot-sourcing (the tests do this) loads the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') {
    $client = Connect-Rsc $ServiceAccount
    if ($Preflight) { exit (Invoke-Preflight $client) }
    Invoke-Collect $client $Customer $Out $Redact.IsPresent
}
