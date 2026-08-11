Write-Host "=== 1. Login as userA and userB ==="
$bodyA = @{ username = "userA"; password = "passwordA" } | ConvertTo-Json
$bodyB = @{ username = "userB"; password = "passwordB" } | ConvertTo-Json
$loginA = Invoke-RestMethod -Uri http://localhost:8080/auth/login -Method Post -Body $bodyA -ContentType "application/json"
$loginB = Invoke-RestMethod -Uri http://localhost:8080/auth/login -Method Post -Body $bodyB -ContentType "application/json"
Write-Host "userA token obtained: $($loginA.token.Substring(0,20))..."
Write-Host "userB token obtained: $($loginB.token.Substring(0,20))..."

Write-Host "`n=== 2. Manual IDOR check: create as A, read as B ==="
$createBody = @{ name = "Verification Test"; volume = 100; type = "freshwater" } | ConvertTo-Json
$created = Invoke-RestMethod -Uri http://localhost:8080/aquariums -Method Post -Body $createBody -ContentType "application/json" -Headers @{ Authorization = "Bearer $($loginA.token)" }
$aquariumId = $created.data.id
Write-Host "Created aquarium id: $aquariumId as userA"

try {
    $readAsB = Invoke-RestMethod -Uri "http://localhost:8080/aquariums/$aquariumId" -Headers @{ Authorization = "Bearer $($loginB.token)" }
    Write-Host "GET as userB: 200 OK -> IDOR present (expected, this is the intentional fixture)"
} catch {
    Write-Host "GET as userB: FAILED with status $($_.Exception.Response.StatusCode.value__) -> WARNING"
}

try {
    Invoke-RestMethod -Uri "http://localhost:8080/aquariums/$aquariumId" -Method Delete -Headers @{ Authorization = "Bearer $($loginB.token)" }
    Write-Host "DELETE as userB: SUCCEEDED -> WARNING, this should have been blocked (403)"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 403) { Write-Host "DELETE as userB: 403 -> correct" } else { Write-Host "DELETE as userB: status $status -> unexpected" }
}

Write-Host "`n=== 3. Manual BFLA check: GET /admin/users as userA ==="
try {
    $adminUsers = Invoke-RestMethod -Uri "http://localhost:8080/admin/users" -Headers @{ Authorization = "Bearer $($loginA.token)" }
    Write-Host "GET /admin/users as userA: 200 OK -> BFLA present (expected, this is the intentional fixture)"
    $adminUsers | ConvertTo-Json -Depth 5
} catch {
    Write-Host "GET /admin/users as userA: FAILED with status $($_.Exception.Response.StatusCode.value__) -> WARNING"
}

try {
    Invoke-RestMethod -Uri "http://localhost:8080/admin/users" | Out-Null
    Write-Host "GET /admin/users with no token: SUCCEEDED -> WARNING, this should have been blocked (401)"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 401) { Write-Host "GET /admin/users with no token: 401 -> correct" } else { Write-Host "GET /admin/users with no token: status $status -> unexpected" }
}

Write-Host "`n=== 4. Rate-limit check on /auth/login (should block after 5 attempts/60s) ==="
$wrongBody = @{ username = "userA"; password = "wrong" } | ConvertTo-Json
for ($i = 1; $i -le 6; $i++) {
    try {
        Invoke-RestMethod -Uri http://localhost:8080/auth/login -Method Post -Body $wrongBody -ContentType "application/json" | Out-Null
        Write-Host "Attempt $i : no error (unexpected)"
    } catch {
        Write-Host "Attempt $i : status $($_.Exception.Response.StatusCode.value__)"
    }
}

Write-Host "`n=== 5. Automated Sentinel scan with both identities (IDOR + BFLA) ==="
# Requires SENTINEL_SCAN_IDOR_ENABLED=true and SENTINEL_SCAN_BFLA_ENABLED=true in .env.dev,
# and the sentinel-dev container rebuilt/restarted with --env-file .env.dev for both to
# actually run instead of silently no-op'ing.
$scanBody = @{
    targetUrl = "http://api-gateway:8080"
    identities = @{
        a = @{ header = "Authorization"; value = "Bearer $($loginA.token)" }
        b = @{ header = "Authorization"; value = "Bearer $($loginB.token)" }
    }
} | ConvertTo-Json -Depth 5
Write-Host $scanBody
$scanResult = Invoke-RestMethod -Uri http://localhost:8088/api/scans -Method Post -Body $scanBody -ContentType "application/json"
$scanResult | ConvertTo-Json -Depth 6
