# End to end inside the image, from Windows PowerShell: web app, API, restart on the same volume, CLI.
# Needs Docker Desktop. Usage: .\tools\docker_e2e.ps1 [-Image subnetplan]
param([string]$Image = "subnetplan")
$ErrorActionPreference = "Stop"

$id = Get-Random
$vol = "subnetplan-e2e-$id"
$name = "subnetplan-e2e-$id"
$script:base = ""

function Start-App {
    docker run -d --name $name --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp -v "${vol}:/data" -p "127.0.0.1::8080" $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "docker run failed" }
    # Docker picks a free port (Windows reserves some ranges, so a fixed one can be refused)
    $mapped = (docker port $name 8080/tcp | Select-Object -First 1)
    $script:base = "http://127.0.0.1:" + ($mapped -split ":")[-1]
    for ($i = 0; $i -lt 60; $i++) {
        try { Invoke-WebRequest -UseBasicParsing "$($script:base)/api/audit" | Out-Null; return } catch { Start-Sleep -Milliseconds 500 }
    }
    docker logs $name
    throw "the server did not come up"
}
function Invoke-Api($method, $path, $body) {
    $req = @{ Method = $method; Uri = "$($script:base)$path"; ContentType = "application/json"; UseBasicParsing = $true }
    if ($body) { $req.Body = $body }
    (Invoke-WebRequest @req).Content
}
function Assert-Contains($text, $needle) { if ($text -notmatch [regex]::Escape($needle)) { throw "expected '$needle' in: $text" } }

try {
    Start-App
    Assert-Contains (Invoke-Api POST "/api/prefixes" '{"cidr":"10.0.0.0/22","name":"site","status":"container"}') '"id":1'
    Assert-Contains (Invoke-Api POST "/api/prefixes/1/allocate" '{"name":"office","hosts":200}') '"cidr":"10.0.0.0/24"'
    Assert-Contains (Invoke-Api POST "/api/plan" '{"network":"10.9.0.0/24","requests":[{"name":"a","hosts":100},{"name":"b","hosts":50}]}') "10.9.0.128/26"
    $page = Invoke-WebRequest -UseBasicParsing "$($script:base)/"
    Assert-Contains $page.Headers["Content-Security-Policy"] "default-src 'self'"
    # an invalid prefix must be refused with 422 (the exception type differs between PowerShell 5.1 and 7)
    $status = 0
    try { Invoke-Api POST "/api/prefixes" '{"cidr":"10.0.0.0/33"}' | Out-Null } catch { $status = [int]$_.Exception.Response.StatusCode }
    if ($status -ne 422) { throw "expected HTTP 422 for an invalid prefix, got $status" }

    docker rm -f $name | Out-Null
    Start-App
    Assert-Contains (Invoke-Api GET "/api/prefixes" $null) "10.0.0.0/24"
    docker rm -f $name | Out-Null

    $ls = docker run --rm --read-only --cap-drop ALL -v "${vol}:/data" $Image ipam --db /data/ipam.db ls
    Assert-Contains ($ls | Out-String) "office"
    $plan = docker run --rm $Image plan 10.0.0.0/24 --need lan=100 --need wifi=50
    Assert-Contains ($plan | Out-String) "10.0.0.128/26"
    Write-Host "docker end-to-end: OK"
}
finally {
    docker rm -f $name 2>$null | Out-Null
    docker volume rm -f $vol 2>$null | Out-Null
}
