param(
    [string]$ApiBase = $(if ($env:API_BASE) { $env:API_BASE } else { "http://localhost:8080" }),
    [string]$Username = $(if ($env:DEMO_USER) { $env:DEMO_USER } else { "admin" }),
    [string]$Password = $(if ($env:DEMO_PASS) { $env:DEMO_PASS } else { "admin123" }),
    [int]$PauseSeconds = 2,
    [switch]$IncludeExtendedScenarios,
    [switch]$SkipRateLimitDemo,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_demo_common.ps1")

function Write-JudgeStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ""
    Write-Host "[judge-demo] $Message" -ForegroundColor Cyan
}

function Write-JudgeSuccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[ok] $Message" -ForegroundColor Green
}

function Write-JudgeWarn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[warn] $Message" -ForegroundColor Yellow
}

function Get-HttpStatusCode {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    try {
        return [int]$ErrorRecord.Exception.Response.StatusCode.value__
    } catch {
        try {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        } catch {
            return $null
        }
    }
}

function Test-GatewayReadiness {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase
    )

    Write-JudgeStep "Checking gateway health and service readiness"
    if ($DryRun) {
        Write-Host "Would call: GET $ApiBase/health"
        Write-Host "Would call: GET $ApiBase/ready"
        return $true
    }

    $healthy = $false
    try {
        $health = Invoke-RestMethod -Method Get -Uri "$ApiBase/health" -ErrorAction Stop
        $healthy = $health.status -eq "healthy"
    } catch {
        Write-JudgeWarn "Health check failed: $($_.Exception.Message)"
        return $false
    }

    try {
        $ready = Invoke-RestMethod -Method Get -Uri "$ApiBase/ready" -ErrorAction Stop
        $services = @($ready.services.PSObject.Properties)
        $unhealthy = @($services | Where-Object { $_.Value -ne "healthy" })
        Write-JudgeSuccess "Gateway reachable. Unhealthy services: $($unhealthy.Count)"
    } catch {
        Write-JudgeWarn "Readiness endpoint is not reachable: $($_.Exception.Message)"
    }

    return $healthy
}

function Test-ProtectedRouteWithoutToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase
    )

    Write-JudgeStep "Protection check 1: call protected route with no token"
    if ($DryRun) {
        Write-Host "Would call: GET $ApiBase/api/v1/soar/incidents (without Authorization header)"
        return $true
    }

    try {
        $null = Invoke-RestMethod -Method Get -Uri "$ApiBase/api/v1/soar/incidents" -ErrorAction Stop
        Write-JudgeWarn "Protected route unexpectedly allowed anonymous access."
        return $false
    } catch {
        $statusCode = Get-HttpStatusCode -ErrorRecord $_
        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            Write-JudgeSuccess "Unauthorized request blocked with HTTP $statusCode."
            return $true
        }

        Write-JudgeWarn "Unexpected response code while testing unauthorized access: $statusCode"
        return $false
    }
}

function Test-ProtectedRouteWithInvalidToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase
    )

    Write-JudgeStep "Protection check 2: call protected route with invalid JWT"
    if ($DryRun) {
        Write-Host "Would call: GET $ApiBase/api/v1/soar/incidents with Authorization: Bearer invalid-demo-token"
        return $true
    }

    $headers = @{
        Authorization = "Bearer invalid-demo-token"
    }

    try {
        $null = Invoke-RestMethod -Method Get -Uri "$ApiBase/api/v1/soar/incidents" -Headers $headers -ErrorAction Stop
        Write-JudgeWarn "Protected route unexpectedly accepted an invalid token."
        return $false
    } catch {
        $statusCode = Get-HttpStatusCode -ErrorRecord $_
        if ($statusCode -eq 401 -or $statusCode -eq 403) {
            Write-JudgeSuccess "Invalid token was rejected with HTTP $statusCode."
            return $true
        }

        Write-JudgeWarn "Unexpected response code while testing invalid token handling: $statusCode"
        return $false
    }
}

function Invoke-ScenarioScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ApiBase,
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$Password,
        [int]$PauseSeconds = 0
    )

    Write-JudgeStep "Scenario: $Name"

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Scenario script not found: $Path"
    }

    if ($DryRun) {
        Write-Host "Would run: $Path -ApiBase $ApiBase -Username $Username -Password ******"
        return $true
    }

    try {
        & $Path -ApiBase $ApiBase -Username $Username -Password $Password
        Write-JudgeSuccess "$Name completed."
        if ($PauseSeconds -gt 0) {
            Start-Sleep -Seconds $PauseSeconds
        }
        return $true
    } catch {
        Write-JudgeWarn "$Name failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-RateLimitProtection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiBase,
        [int]$Requests = 130
    )

    Write-JudgeStep "Protection check 3: controlled burst to prove rate limiting"
    if ($DryRun) {
        Write-Host "Would run: $Requests GET requests to $ApiBase/health and expect HTTP 429"
        return $true
    }

    $hitAt = 0
    for ($i = 1; $i -le $Requests; $i++) {
        try {
            $null = Invoke-WebRequest -Method Get -Uri "$ApiBase/health" -UseBasicParsing -ErrorAction Stop
        } catch {
            $statusCode = Get-HttpStatusCode -ErrorRecord $_
            if ($statusCode -eq 429) {
                $hitAt = $i
                break
            }

            Write-JudgeWarn "Rate limit burst interrupted by unexpected status code: $statusCode"
            return $false
        }
    }

    if ($hitAt -gt 0) {
        Write-JudgeSuccess "Rate limit enforced at request #$hitAt (HTTP 429)."
        Write-Host "Tip: wait 60 seconds before rerunning this script from the same host."
        return $true
    }

    Write-JudgeWarn "Did not observe HTTP 429 within $Requests requests."
    return $false
}

$results = [ordered]@{
    gateway_ready           = $false
    unauthorized_blocked    = $false
    invalid_token_blocked   = $false
    threat_wave             = $false
    anonymous_phishing      = $false
    incident_response       = $false
    malware_burst           = $null
    ransomware_scenario     = $null
    rate_limit_blocked      = $null
}

$scriptRoot = $PSScriptRoot
$threatWaveScript = Join-Path $scriptRoot "Invoke-ThreatWave.ps1"
$phishingScript = Join-Path $scriptRoot "Invoke-AnonymousPhishing.ps1"
$incidentScript = Join-Path $scriptRoot "Invoke-IncidentResponse.ps1"
$malwareScript = Join-Path $scriptRoot "Invoke-MalwareBurst.ps1"
$ransomwareScript = Join-Path $scriptRoot "Invoke-RansomwareScenario.ps1"

Write-Host "==============================================="
Write-Host " Pariraksakah Safe Judge Demo"
Write-Host " Local simulation only. Do not target real systems."
Write-Host "==============================================="

$results.gateway_ready = Test-GatewayReadiness -ApiBase $ApiBase
$results.unauthorized_blocked = Test-ProtectedRouteWithoutToken -ApiBase $ApiBase
$results.invalid_token_blocked = Test-ProtectedRouteWithInvalidToken -ApiBase $ApiBase

$results.threat_wave = Invoke-ScenarioScript `
    -Name "Threat wave detection" `
    -Path $threatWaveScript `
    -ApiBase $ApiBase `
    -Username $Username `
    -Password $Password `
    -PauseSeconds $PauseSeconds

$results.anonymous_phishing = Invoke-ScenarioScript `
    -Name "Anonymous phishing escalation" `
    -Path $phishingScript `
    -ApiBase $ApiBase `
    -Username $Username `
    -Password $Password `
    -PauseSeconds $PauseSeconds

$results.incident_response = Invoke-ScenarioScript `
    -Name "Incident response and audit chain" `
    -Path $incidentScript `
    -ApiBase $ApiBase `
    -Username $Username `
    -Password $Password `
    -PauseSeconds $PauseSeconds

if ($IncludeExtendedScenarios) {
    $results.malware_burst = Invoke-ScenarioScript `
        -Name "Extended: malware burst" `
        -Path $malwareScript `
        -ApiBase $ApiBase `
        -Username $Username `
        -Password $Password `
        -PauseSeconds $PauseSeconds

    $results.ransomware_scenario = Invoke-ScenarioScript `
        -Name "Extended: ransomware response" `
        -Path $ransomwareScript `
        -ApiBase $ApiBase `
        -Username $Username `
        -Password $Password `
        -PauseSeconds $PauseSeconds
}

if (-not $SkipRateLimitDemo) {
    $results.rate_limit_blocked = Test-RateLimitProtection -ApiBase $ApiBase
}

Write-Host ""
Write-Host "Judge demo summary"
Write-Host "------------------"
foreach ($item in $results.GetEnumerator()) {
    if ($null -eq $item.Value) {
        Write-Host ("{0,-24} {1}" -f $item.Key, "skipped")
        continue
    }

    $statusText = if ([bool]$item.Value) { "pass" } else { "check" }
    Write-Host ("{0,-24} {1}" -f $item.Key, $statusText)
}

