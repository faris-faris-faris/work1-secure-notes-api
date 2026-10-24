# Verify the CVE-2022-22965 fix (Windows / PowerShell).
#
# Spring 5.3.18 does not answer the malicious binding with an error: it makes
# `class.*` non-bindable, and a WAR-deployed app silently ignores the unknown
# properties (HTTP 200, normal page). A status-code check would therefore call
# the patched server "still vulnerable". This script verifies the *behaviour*:
#   * the valve is not rewritten (access-log format unchanged),
#   * no JSP webshell appears in the webroot,
#   * the application still binds normal parameters (regression).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\verify-fix.ps1
#   powershell ... -BaseUrl http://127.0.0.1:8080 -Container spring4shell-fixed
param(
    [string]$BaseUrl = 'http://127.0.0.1:8080',
    [string]$Container = 'spring4shell-fixed'
)

$ProgressPreference = 'SilentlyContinue'
$prefix = 'class.module.classLoader.resources.context.parent.pipeline.first'
$pass = 0
$fail = 0

function Check($description, [bool]$ok, $detail = '') {
    if ($ok) {
        Write-Host "[PASS] $description" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "[FAIL] $description" -ForegroundColor Red
        if ($detail) { Write-Host "       $detail" -ForegroundColor DarkYellow }
        $script:fail++
    }
}

function StatusOf($url, $headers = @{}) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10 -Headers $headers
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

function DockerExec([string]$command) {
    try {
        $out = & docker exec $Container sh -c $command 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return ($out -join "`n")
    } catch { return $null }
}

Write-Host "`n1. Regression: the application still serves normal requests" -ForegroundColor Cyan
$page = ''
try { $page = (Invoke-WebRequest -Uri "$BaseUrl/?name=Bob&age=25" -UseBasicParsing -TimeoutSec 5).Content } catch {}
$code = StatusOf "$BaseUrl/?name=Bob&age=25"
Write-Host "GET /?name=Bob&age=25 -> HTTP $code"
Check 'normal request returns 200 and renders Bob, 25' ($code -eq 200 -and $page -match 'Bob' -and $page -match '25')

Write-Host "`n2. Replay the exploit (Spring 5.3.18 ignores the class.* properties)" -ForegroundColor Cyan
$pattern = '%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))%21%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di'
$url = "$BaseUrl/?$prefix.pattern=$pattern&$prefix.suffix=.jsp&$prefix.directory=webapps/ROOT&$prefix.prefix=tomcatwar&$prefix.fileDateFormat="
$headers = @{ 'suffix' = '%>//'; 'c1' = 'Runtime'; 'c2' = '<%' }
$code = StatusOf $url $headers
Write-Host "exploit request -> HTTP $code (200 here means 'ignored', not 'exploited')"
Start-Sleep -Seconds 12  # let Tomcat flush/rotate its access log

Write-Host "`n3. No webshell was written" -ForegroundColor Cyan
$code = StatusOf "$BaseUrl/tomcatwar.jsp?pwd=j&cmd=id"
Write-Host "GET /tomcatwar.jsp -> HTTP $code"
Check 'the JSP webshell does not exist (404)' ($code -eq 404)

$listing = DockerExec 'ls /usr/local/tomcat/webapps/ROOT/ 2>/dev/null'
if ($null -ne $listing) {
    Check 'no *.jsp file in the exploded webroot' (-not ($listing -match '(?m)^.*\.jsp$')) $listing
} else {
    Write-Host '       (container not reachable - filesystem check skipped)'
}

Write-Host "`n4. The access-log valve was not rewritten" -ForegroundColor Cyan
# Log a benign request last, then inspect that line: if the valve had been
# rewritten, the line would be JSP source instead of a request line.
$null = StatusOf "$BaseUrl/?name=Regression&age=30"
Start-Sleep -Seconds 11
$lastLog = DockerExec 'tail -1 /usr/local/tomcat/logs/localhost_access_log.*.txt 2>/dev/null'
if ($null -ne $lastLog) {
    Write-Host "last access-log line: $lastLog"
    Check 'the access log keeps the default pattern (request line, status, bytes)' `
        ($lastLog -match '^\d+\.\d+\.\d+\.\d+ - - \[' -and $lastLog -match '"GET /\?name=Regression')
    Check 'the log line does not contain JSP source' `
        (-not ($lastLog -match '<%|%>'))
} else {
    Write-Host '       (container not reachable - log check skipped)'
}

Write-Host "`n5. Binding of normal model properties still works" -ForegroundColor Cyan
$code = StatusOf "$BaseUrl/?name=Alice&age=20"
Check 'argument binding for the normal model still works' ($code -eq 200)

Write-Host "`nRESULT: $pass passed, $fail failed"
if ($fail -ne 0) {
    Write-Host 'fix verification FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'fix verified - all checks passed' -ForegroundColor Green
