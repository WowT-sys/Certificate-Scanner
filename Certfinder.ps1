[CmdletBinding()]
param (
    [string]$cfg,
    [string]$dir,
    [string[]]$ext = @(".exe", ".dll", ".msi", ".sys", ".ocx", ".cab", ".cat", ".ps1", ".jar", ".apk", ".appx", ".msix"),
    [int]$thresh = 30,
    [object]$csv,
    [object]$html,
    [switch]$expired,
    [switch]$par,
    [switch]$unsigned,
    [switch]$v,
    [switch]$hash,
    [int]$depth = -1,
    [string[]]$exclude = @(),
    [switch]$fast,
    [switch]$signedOnly,
    [int]$maxFiles = 0,
    [int]$threads = 0
)

# If "fast" mode is enabled, adjust settings for maximum performance
if ($fast) {
    $hash = $false           # Skip hash calculation to save time
    $par = $true            # Enable parallel processing
    $signedOnly = $true     # Focus only on files likely to be signed
    if ($threads -eq 0) {
        $threads = [Environment]::ProcessorCount * 2
    }
    Write-Host "Fast mode enabled - optimized for maximum performance" -ForegroundColor Yellow
}

# Auto-detect thread count if not specified
if ($threads -eq 0) {
    $threads = [Math]::Min([Environment]::ProcessorCount * 2, 20)
}

# # Skip unnecessary file types in signed-only mode
$skipExtensions = @('.txt', '.log', '.ini', '.cfg', '.xml', '.json', '.csv', '.md', '.rtf', '.pdf', '.doc', '.docx')
if ($signedOnly) {
    $originalExtCount = $ext.Count
    $ext = $ext | Where-Object { $_ -notin $skipExtensions }
    Write-Host "Signed-only mode: reduced extensions from $originalExtCount to $($ext.Count)" -ForegroundColor Yellow
}

# Initialize caches for performance
$script:CertificateCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()
$script:FileCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()

# Handle CSV and HTML output paths
if ($csv -is [switch] -and $csv) {
    $csvPath = "CertificateScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $exportCsv = $true
} elseif ($csv -is [string] -and $csv) {
    $csvPath = $csv
    $exportCsv = $true
} else {
    $csvPath = "CertificateScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $exportCsv = $false
}

if ($html -is [switch] -and $html) {
    $htmlPath = "CertificateScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $exportHtml = $true
} elseif ($html -is [string] -and $html) {
    $htmlPath = $html
    $exportHtml = $true
} else {
    $htmlPath = "CertificateScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $exportHtml = $false
}

# Load configuration file if provided
if ($cfg -and (Test-Path -Path $cfg)) {
    Write-Host "Loading configuration from: $cfg" -ForegroundColor Cyan
    try {
        # Load the JSON configuration file
        Write-Host "Configuration loaded successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to load configuration file: $($_.Exception.Message)"
    }
}

# Ensure the directory parameter is provided
if (-not $dir) {
    throw "Directory path is required. Provide it as -dir parameter or in the configuration file."
}

# Function to quickly get directories, skipping excluded ones
function Get-DirectoriesFast {
    param (
        [string]$RootPath,
        [int]$MaxDepth = -1,
        [string[]]$ExcludeDirectories = @()
    )
    
    try {
        $directories = [System.Collections.Generic.List[string]]::new()
        $queue = [System.Collections.Generic.Queue[object]]::new()
        
        # Start with the root directory
        $queue.Enqueue([PSCustomObject]@{ Path = $RootPath; Depth = 0 })
        $directories.Add($RootPath)
        
        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()
            
            # Stop if we've reached the maximum depth
            if ($MaxDepth -ne -1 -and $current.Depth -ge $MaxDepth) {
                continue
            }
            
            try {
                # Use .NET for fast directory enumeration
                $dirInfo = [System.IO.DirectoryInfo]::new($current.Path)
                $subdirs = $dirInfo.GetDirectories()
                
                foreach ($subdir in $subdirs) {
                    # Skip excluded directories
                    $shouldExclude = $false
                    if ($ExcludeDirectories.Count -gt 0) {
                        foreach ($excludePattern in $ExcludeDirectories) {
                            if ($subdir.Name -like $excludePattern) {
                                $shouldExclude = $true
                                break
                            }
                        }
                    }
                    
                    if (-not $shouldExclude) {
                        $directories.Add($subdir.FullName)
                        $queue.Enqueue([PSCustomObject]@{ 
                            Path = $subdir.FullName; 
                            Depth = $current.Depth + 1 
                        })
                    }
                }
            }
            catch {
                # Skip directories we can't access
                continue
            }
        }
        
        return $directories.ToArray()
    }
    catch {
        Write-Warning "Fast directory enumeration failed, using fallback"
        return @($RootPath)
    }
}

# Function to quickly get files from directories
function Get-FilesFast {
    param (
        [string[]]$Directories,
        [string[]]$Extensions,
        [int]$MaxFiles = 0
    )
    
    $allFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $fileCount = 0
    
    # Convert extensions to search patterns
    $patterns = $Extensions | ForEach-Object { "*$_" }
    
    foreach ($directory in $Directories) {
        if ($MaxFiles -gt 0 -and $fileCount -ge $MaxFiles) {
            break
        }
        
        try {
            $dirInfo = [System.IO.DirectoryInfo]::new($directory)
            
            foreach ($pattern in $patterns) {
                if ($MaxFiles -gt 0 -and $fileCount -ge $MaxFiles) {
                    break
                }
                
                try {
                    $files = $dirInfo.GetFiles($pattern, [System.IO.SearchOption]::TopDirectoryOnly)
                    
                    foreach ($file in $files) {
                        if ($MaxFiles -gt 0 -and $fileCount -ge $MaxFiles) {
                            break
                        }
                        
                        # Skip tiny files in signed-only mode
                        if ($signedOnly -and $file.Length -lt 1024) {
                            continue
                        }
                        
                        $allFiles.Add($file)
                        $fileCount++
                    }
                }
                catch {
                    continue
                }
            }
        }
        catch {
            continue
        }
    }
    
    return $allFiles.ToArray()
}

# Function to check file certificates with caching
function Get-FileCertificateFast {
    param (
        [System.IO.FileInfo]$FileInfo,
        [int]$ThresholdDays = 30
    )
    
    try {
        # Create a cache key based on file attributes
        $cacheKey = "$($FileInfo.FullName)|$($FileInfo.Length)|$($FileInfo.LastWriteTime.Ticks)"
        
        # Check if the result is already cached
        if ($script:CertificateCache.TryGetValue($cacheKey, [ref]$null)) {
            return $script:CertificateCache[$cacheKey]
        }
        
        $ext = $FileInfo.Extension.ToLower()
        if ($signedOnly -and $ext -in $skipExtensions) {
            $result = [PSCustomObject]@{
                FilePath = $FileInfo.FullName
                FileName = $FileInfo.Name
                FileExtension = $ext
                Status = "Not Signed"
                FileSize = [math]::Round($FileInfo.Length / 1MB, 2)
                LastModified = $FileInfo.LastWriteTime
                ExpiryDate = $null
                DaysLeft = $null
                IsExpired = $false
                IsExpiringSoon = $false
            }
            $script:CertificateCache.TryAdd($cacheKey, $result) | Out-Null
            return $result
        }
        
        # Initialize result object
        $result = [PSCustomObject]@{
            FilePath        = $FileInfo.FullName
            FileName        = $FileInfo.Name
            FileExtension   = $FileInfo.Extension
            FileSize        = [math]::Round($FileInfo.Length / 1MB, 2)
            LastModified    = $FileInfo.LastWriteTime
            Status          = "Unknown"
            ExpiryDate      = $null
            DaysLeft        = $null
            IsExpired       = $false
            IsExpiringSoon  = $false
            Issuer          = $null
            Subject         = $null
            SerialNumber    = $null
            Thumbprint      = $null
            SignatureType   = $null
            TimeStamped     = $false
            FileHash        = $null
            ErrorMessage    = $null
        }
        
        # Get file hash only if enabled
        if ($hash) {
            try {
                $hashResult = Get-FileHash -Path $FileInfo.FullName -Algorithm SHA256 -ErrorAction Stop
                $result.FileHash = $hashResult.Hash
            }
            catch {
                $result.FileHash = "Error calculating hash"
            }
        }
        
        # Handle JAR files separately
        if ($ext -eq ".jar") {
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [System.IO.Compression.ZipFile]::OpenRead($FileInfo.FullName)
                $hasSignature = $zip.Entries | Where-Object { 
                    $_.FullName -like "META-INF/*.RSA" -or 
                    $_.FullName -like "META-INF/*.DSA" -or 
                    $_.FullName -like "META-INF/*.EC" 
                } | Select-Object -First 1
                
                $zip.Dispose()
                
                if ($hasSignature) {
                    $result.Status = "Valid"
                    $result.SignatureType = "JAR Signature"
                } else {
                    $result.Status = "Not Signed"
                }
            }
            catch {
                $result.Status = "Error"
                $result.ErrorMessage = $_.Exception.Message
            }
        }
        else {
            # Check the file's signature
            try {
                $signature = Get-AuthenticodeSignature -FilePath $FileInfo.FullName -ErrorAction Stop
                $result.Status = $signature.Status.ToString()
                
                if ($signature.Status -eq 'Valid' -and $signature.SignerCertificate) {
                    $cert = $signature.SignerCertificate
                    $expiryDate = $cert.NotAfter
                    $daysLeft = ($expiryDate - (Get-Date)).Days
                    
                    $result.ExpiryDate = $expiryDate
                    $result.DaysLeft = $daysLeft
                    $result.IsExpired = $daysLeft -le 0
                    $result.IsExpiringSoon = $daysLeft -le $ThresholdDays -and $daysLeft -gt 0
                    $result.Issuer = $cert.Issuer
                    $result.Subject = $cert.Subject
                    $result.SerialNumber = $cert.SerialNumber
                    $result.Thumbprint = $cert.Thumbprint
                    $result.SignatureType = $signature.SignatureType
                    $result.TimeStamped = $null -ne $signature.TimeStamperCertificate
                }
                elseif ($signature.Status -eq 'NotSigned') {
                    $result.Status = "Not Signed"
                }
                else {
                    $result.ErrorMessage = $signature.StatusMessage
                }
            }
            catch {
                $result.Status = "Error"
                $result.ErrorMessage = $_.Exception.Message
            }
        }
        
        # Cache the result for future use
        $script:CertificateCache.TryAdd($cacheKey, $result) | Out-Null
        return $result
    }
    catch {
        return [PSCustomObject]@{
            FilePath = $FileInfo.FullName
            FileName = $FileInfo.Name
            Status = "Error"
            ErrorMessage = $_.Exception.Message
        }
    }
}

# Memory cleanup
function Clear-MemoryPeriodically {
    param ([int]$Counter)
    
    if ($Counter % 2000 -eq 0) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-DirectoryCertificatesFast {
    param (
        [string]$DirectoryPath,
        [string[]]$Extensions,
        [int]$ThresholdDays,
        [bool]$UseParallel = $true,
        [bool]$IncludeUnsigned = $false,
        [int]$MaxDepth = -1,
        [string[]]$ExcludeDirectories = @(),
        [int]$MaxFiles = 0,
        [int]$ThreadCount = 10
    )
    
    Write-Host "=== PERFORMANCE OPTIMIZED SCAN ===" -ForegroundColor Green
    Write-Host "Directory: $DirectoryPath" -ForegroundColor Gray
    Write-Host "Extensions: $($Extensions -join ', ')" -ForegroundColor Gray
    Write-Host "Max files: $(if ($MaxFiles -eq 0) { 'Unlimited' } else { $MaxFiles })" -ForegroundColor Gray
    Write-Host "Threads: $ThreadCount" -ForegroundColor Gray
    Write-Host "Parallel: $UseParallel" -ForegroundColor Gray
    
    try {
        # directory discovery
        Write-Host "Discovering directories..." -ForegroundColor Yellow
        $directories = Get-DirectoriesFast -RootPath $DirectoryPath -MaxDepth $MaxDepth -ExcludeDirectories $ExcludeDirectories
        Write-Host "Found $($directories.Count) directories" -ForegroundColor Yellow
        
        # file discovery
        Write-Host "Discovering files..." -ForegroundColor Yellow
        $allFiles = Get-FilesFast -Directories $directories -Extensions $Extensions -MaxFiles $MaxFiles
        Write-Host "Found $($allFiles.Count) files to scan" -ForegroundColor Yellow
        
        if ($allFiles.Count -eq 0) {
            Write-Warning "No files found with the specified extensions."
            return @()
        }
        
        # Process files
        $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        
        if ($UseParallel -and $PSVersionTable.PSVersion.Major -ge 7) {
            Write-Host "Processing files in parallel with $ThreadCount threads..." -ForegroundColor Cyan
            
            # parallel processing
            $allFiles | ForEach-Object -Parallel {
                $file = $_
                $thresh = $using:ThresholdDays
                
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                    
                    $result = [PSCustomObject]@{
                        FilePath = $file.FullName
                        FileName = $file.Name
                        FileExtension = $file.Extension
                        Status = if ($signature) { $signature.Status.ToString() } else { "Error" }
                        FileSize = [math]::Round($file.Length / 1MB, 2)
                        LastModified = $file.LastWriteTime
                        ExpiryDate = $null
                        DaysLeft = $null
                        IsExpired = $false
                        IsExpiringSoon = $false
                        Issuer = $null
                        Subject = $null
                    }
                    
                    if ($signature -and $signature.SignerCertificate) {
                        $cert = $signature.SignerCertificate
                        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
                        
                        $result.ExpiryDate = $cert.NotAfter
                        $result.DaysLeft = $daysLeft
                        $result.IsExpired = $daysLeft -le 0
                        $result.IsExpiringSoon = $daysLeft -le $thresh -and $daysLeft -gt 0
                        $result.Issuer = $cert.Issuer
                        $result.Subject = $cert.Subject
                    }
                    
                    return $result
                }
                catch {
                    return [PSCustomObject]@{
                        FilePath = $file.FullName
                        FileName = $file.Name
                        Status = "Error"
                        ErrorMessage = $_.Exception.Message
                    }
                }
            } -ThrottleLimit $ThreadCount
        }
        else {
            # sequential processing
            Write-Host "Processing files sequentially..." -ForegroundColor Cyan
            $counter = 0
            
            foreach ($file in $allFiles) {
                $counter++
                
                if ($counter % 100 -eq 0) {
                    $percentComplete = [math]::Round(($counter / $allFiles.Count) * 100, 1)
                    Write-Progress -Activity "Certificate Analysis" -Status "Processed $counter/$($allFiles.Count) files" -PercentComplete $percentComplete
                    Clear-MemoryPeriodically -Counter $counter
                }
                
                $result = Get-FileCertificateFast -FileInfo $file -ThresholdDays $ThresholdDays
                if ($result) {
                    $results.Add($result)
                }
            }
            Write-Progress -Activity "Certificate Analysis" -Completed
        }
        
        # Convert concurrent bag to array and filter
        $finalResults = $results.ToArray()
        
        if (-not $IncludeUnsigned) {
            $finalResults = $finalResults | Where-Object { $_.Status -ne "Not Signed" }
        }
        
        return $finalResults
    }
    catch {
        Write-Error "Error in fast scanning: $($_.Exception.Message)"
        return @()
    }
}

# helper functions
function Get-CertificateSummary {
    param ([array]$Results)
    
    $summary = [PSCustomObject]@{
        TotalFiles          = $Results.Count
        ValidCertificates   = ($Results | Where-Object { $_.Status -eq "Valid" }).Count
        ExpiredCertificates = ($Results | Where-Object { $_.IsExpired -eq $true }).Count
        ExpiringSoon        = ($Results | Where-Object { $_.IsExpiringSoon -eq $true }).Count
        InvalidSignatures   = ($Results | Where-Object { $_.Status -like "*Invalid*" -or $_.Status -eq "Error" }).Count
        UnsignedFiles       = ($Results | Where-Object { $_.Status -eq "Not Signed" }).Count
        FileTypesScanned    = ($Results | Group-Object FileExtension | Measure-Object).Count
    }
    
    return $summary
}

function Show-ColoredResults {
    param ([array]$Results)
    
    foreach ($result in $Results) {
        $color = switch ($result.Status) {
            "Valid" { 
                if ($result.IsExpired) { "Red" }
                elseif ($result.IsExpiringSoon) { "Yellow" }
                else { "Green" }
            }
            "Not Signed" { "Gray" }
            default { "Red" }
        }
        
        $statusText = if ($result.IsExpired) { "EXPIRED" }
                     elseif ($result.IsExpiringSoon) { "EXPIRING SOON" }
                     else { $result.Status }
        
        Write-Host "$($result.FileName) - $statusText" -ForegroundColor $color
        if ($null -ne $result.DaysLeft) {
            Write-Host "  Days left: $($result.DaysLeft)" -ForegroundColor $color
        }
    }
}

# HTML report generation
function New-HtmlReportFast {
    param (
        [array]$Results,
        [string]$OutputPath,
        [object]$Summary
    )
    
    try {
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Certificate Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        .summary { background-color: #f8f9fa; padding: 15px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #007bff; color: white; }
        .status-valid { color: green; font-weight: bold; }
        .status-expired { color: red; font-weight: bold; }
        .status-expiring { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Certificate Scan Results</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Files: $($Summary.TotalFiles) | Valid: $($Summary.ValidCertificates) | Expired: $($Summary.ExpiredCertificates) | Expiring Soon: $($Summary.ExpiringSoon)</p>
    </div>
    <table>
        <tr><th>File Name</th><th>Status</th><th>Days Left</th><th>Expiry Date</th></tr>
"@
        
        foreach ($result in $Results) {
            $statusClass = if ($result.IsExpired) { "status-expired" } 
                          elseif ($result.IsExpiringSoon) { "status-expiring" } 
                          else { "status-valid" }
            
            $htmlContent += "<tr><td>$($result.FileName)</td><td class='$statusClass'>$($result.Status)</td><td>$($result.DaysLeft)</td><td>$($result.ExpiryDate)</td></tr>`n"
        }
        
        $htmlContent += @"
    </table>
    <p><small>Generated: $(Get-Date)</small></p>
</body>
</html>
"@
        
        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "HTML report generated: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to generate HTML report: $($_.Exception.Message)"
    }
}

# Main execution starts here
try {
    if (-not (Test-Path -Path $dir -PathType Container)) {
        throw "Directory path '$dir' does not exist or is not accessible."
    }
    
    $startTime = Get-Date
    Write-Host "Starting optimized certificate scan..." -ForegroundColor Green
    
    # Use the fast scanning function
    $results = Get-DirectoryCertificatesFast -DirectoryPath $dir -Extensions $ext -ThresholdDays $thresh -UseParallel $par -IncludeUnsigned $unsigned -MaxDepth $depth -ExcludeDirectories $exclude -MaxFiles $maxFiles -ThreadCount $threads
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`nScan completed in $([math]::Round($duration.TotalSeconds, 2)) seconds" -ForegroundColor Green
    Write-Host "Performance: $([math]::Round($results.Count / $duration.TotalSeconds, 1)) files/second" -ForegroundColor Cyan
    
    # Filter results if requested
    if ($expired) {
        $results = $results | Where-Object { $_.IsExpired -or $_.IsExpiringSoon }
        Write-Host "Showing only expired or expiring certificates..." -ForegroundColor Yellow
    }
    
    # Display summary
    $summary = Get-CertificateSummary -Results $results
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    $summary | Format-List
    
    # Display results
    if ($results.Count -gt 0) {
        Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
        
        if ($v) {
            $results | Format-Table -Property FileName, FileExtension, Status, DaysLeft, ExpiryDate -AutoSize
        } else {
            Show-ColoredResults -Results $results
        }
        
        # Export results
        if ($exportCsv) {
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Host "`nResults exported to: $csvPath" -ForegroundColor Green
        }
        
        if ($exportHtml) {
            New-HtmlReportFast -Results $results -OutputPath $htmlPath -Summary $summary
        }
        
        # Show critical alerts
        $criticalResults = $results | Where-Object { $_.IsExpired -or $_.IsExpiringSoon }
        if ($criticalResults.Count -gt 0) {
            Write-Host "`n=== ATTENTION REQUIRED ===" -ForegroundColor Red
            $criticalResults | Format-Table -Property FileName, Status, DaysLeft, ExpiryDate -AutoSize
        }
    } else {
        Write-Host "No results to display." -ForegroundColor Yellow
    }
    
    # Display cache statistics
    Write-Host "`nCache Statistics:" -ForegroundColor Gray
    Write-Host "Certificate cache entries: $($script:CertificateCache.Count)" -ForegroundColor Gray
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}