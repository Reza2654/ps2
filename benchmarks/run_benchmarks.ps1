$ErrorActionPreference = "Stop"

$ps2Exe = Resolve-Path "src/Ps2.Cli/bin/Release/net10.0/ps2.exe" -ErrorAction SilentlyContinue
if (-not $ps2Exe) {
    Write-Host "Building PS2 in Release mode..."
    dotnet build src/Ps2.Cli/Ps2.Cli.csproj -c Release | Out-Null
    $ps2Exe = Resolve-Path "src/Ps2.Cli/bin/Release/net10.0/ps2.exe"
}

$iterations = 10
Write-Host "=== Benchmarking Cold-Start Automation: PS2 vs Python vs PowerShell ==="
Write-Host "Workload: Load JSON config, parse array of objects, filter active nodes, reduce CPU sum, output result."
Write-Host "Iterations: $iterations runs per engine (cold-start process timing)`n"

function Measure-Runner($name, $cmd, $argsList) {
    Write-Host "Benchmarking $name..."
    $times = @()

    for ($i = 1; $i -le $iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $cmd
        $psi.Arguments = $argsList
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $p = [System.Diagnostics.Process]::Start($psi)
        $p.WaitForExit()
        $sw.Stop()

        if ($p.ExitCode -ne 0) {
            Write-Error "Command failed: $($p.StandardError.ReadToEnd())"
        }

        $times += $sw.Elapsed.TotalMilliseconds
        Start-Sleep -Milliseconds 50
    }

    $sorted = $times | Sort-Object
    $min = [math]::Round($sorted[0], 2)
    $max = [math]::Round($sorted[-1], 2)
    $avg = [math]::Round(($times | Measure-Object -Average).Average, 2)
    $median = [math]::Round($sorted[[math]::Floor($iterations / 2)], 2)

    return [PSCustomObject]@{
        Engine = $name
        "Min (ms)" = $min
        "Median (ms)" = $median
        "Mean (ms)" = $avg
        "Max (ms)" = $max
    }
}

$ps2Result = Measure-Runner "PS2 (v0.4.0)" $ps2Exe.Path "run benchmarks/workload.ps2"
$pythonResult = Measure-Runner "Python (3.12)" "python" "benchmarks/workload.py"
$pwshResult = Measure-Runner "PowerShell (5.1/7)" "powershell" "-ExecutionPolicy Bypass -NoProfile -File benchmarks/workload.ps1"

Write-Host "`n=== BENCHMARK RESULTS ==="
$results = @($ps2Result, $pythonResult, $pwshResult)
$results | Format-Table -AutoSize
