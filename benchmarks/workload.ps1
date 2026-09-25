$data = Get-Content -Raw "benchmarks/data.json" | ConvertFrom-Json
$active = $data | Where-Object { $_.status -eq "active" }
$total_cpu = ($active | Measure-Object -Property cpu -Sum).Sum
Write-Host "PowerShell: Processed $($active.Count) active nodes, Total CPU: $total_cpu"
