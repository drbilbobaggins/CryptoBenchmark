param(
    [switch]$NonObserving
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not $NonObserving) {
    throw 'This safety test runner requires -NonObserving'
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runnerPath = Join-Path $PSScriptRoot 'm23-pilot-session.ps1'
. $runnerPath
$script:M23PilotTestMode = $true
$script:M23PilotChildLaunchCount = 0

$script:passedTests = 0
$script:failedTests = 0

function Assert-Test {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert-Test $threw $Message
}

function Invoke-SafetyTest {
    param([string]$Name, [scriptblock]$Action)
    try {
        & $Action
        $script:passedTests++
        Write-Output "PASS $Name"
    } catch {
        $script:failedTests++
        Write-Output "FAIL $Name :: $($_.Exception.ToString())"
    }
}

function New-TestSelection {
    $document = Get-M23Selection
    $report = Invoke-M23HarnessDryRun `
        (Join-Path $repositoryRoot 'build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe') `
        $script:M23PilotCandidatePlanSha256
    return [pscustomobject]@{
        File = $document
        Report = $report
        Resolved = Resolve-M23Selection $document $report.candidatePlan
    }
}

function New-TestLedgerEntry {
    param(
        [int]$Ordinal,
        [string]$GroupId,
        [int]$Runs,
        [string]$Status,
        [long]$ChargedMilliseconds
    )
    return [ordered]@{
        ordinal = $Ordinal
        groupId = $GroupId
        logicalRuns = $Runs
        reservedMaximumSeconds = 900
        chargedActiveMilliseconds = $ChargedMilliseconds
        reservedAtUtc = '2026-10-31T00:00:00.0000000Z'
        startedAtUtc = '2026-10-31T00:00:00.0000000Z'
        completedAtUtc = '2026-10-31T00:01:00.0000000Z'
        outputPath = 'C:\external\test'
        childExitCode = 0
        status = $Status
        reason = ''
    }
}

function Write-TestSyntheticPilotEvidence {
    param(
        [string]$OutputPath,
        [object]$Group,
        [object]$Approval,
        [object]$Build,
        [string]$EvidenceApprovedPlanSha256,
        [switch]$WrongBatchResultSha256,
        [switch]$CorruptBatchResultAfterMarker
    )
    $resultPath = Join-Path $OutputPath 'batch-result.json'
    [System.IO.File]::WriteAllText(
        $resultPath, '{"synthetic":true}',
        (New-Object System.Text.UTF8Encoding($false)))
    $resultSha256 = Get-M23FileSha256 $resultPath
    if ($WrongBatchResultSha256) {
        $resultSha256 = 'f' * 64
    }
    if ([string]::IsNullOrWhiteSpace($EvidenceApprovedPlanSha256)) {
        $EvidenceApprovedPlanSha256 = $Approval.Sha256
    }
    $evidencePath = Join-Path $OutputPath 'pilot-evidence.json'
    $evidence = [ordered]@{
        status = 'completed'
        evidenceKind = 'realPilotObservation'
        groupId = $Group.GroupId
        candidatePlanSha256 = $script:M23PilotCandidatePlanSha256
        applicationSha256 = $Build.ApplicationSha256
        workerSha256 = $Build.WorkerSha256
        environment = [ordered]@{
            gitCommit = $Build.BuildInfoCommit
            buildType = 'Release'
        }
        approvedPlanSha256 = $EvidenceApprovedPlanSha256
        approvalReference = $Approval.Reference
    }
    [System.IO.File]::WriteAllText(
        $evidencePath,
        (ConvertTo-Json -InputObject $evidence -Depth 20 -Compress),
        (New-Object System.Text.UTF8Encoding($false)))
    $manifestPath = Join-Path $OutputPath 'manifest.json'
    $manifest = [ordered]@{
        status = 'completed'
        approvedPlanSha256 = $Approval.Sha256
        evidenceSha256 = Get-M23FileSha256 $evidencePath
        batchResultSha256 = $resultSha256
        environmentSha256 = 'e' * 64
    }
    [System.IO.File]::WriteAllText(
        $manifestPath,
        (ConvertTo-Json -InputObject $manifest -Depth 20 -Compress),
        (New-Object System.Text.UTF8Encoding($false)))
    $marker = [ordered]@{
        complete = $true
        evidenceSha256 = Get-M23FileSha256 $evidencePath
        manifestSha256 = Get-M23FileSha256 $manifestPath
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $OutputPath 'success.marker'),
        (ConvertTo-Json -InputObject $marker -Compress),
        (New-Object System.Text.UTF8Encoding($false)))
    if ($CorruptBatchResultAfterMarker) {
        [System.IO.File]::WriteAllText(
            $resultPath, '{"synthetic":false}',
            (New-Object System.Text.UTF8Encoding($false)))
    }
}

function Test-PidStopped {
    param([int]$ProcessId)
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        return $false
    } catch {
        return $true
    }
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'cryptobenchmark-m23-tests-' + [Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

try {
    $context = New-TestSelection
    $selection = $context.File
    $resolved = $context.Resolved
    $plan = $context.Report.candidatePlan

    Invoke-SafetyTest 'Selection resolves 23 groups, 27 runs, 12 cases' {
        Assert-Test ($resolved.Count -eq 23) 'group count mismatch'
        $runs = 0
        foreach ($group in $resolved) { $runs += $group.LogicalRuns }
        Assert-Test ($runs -eq 27) 'logical worker-run count mismatch'
        Assert-Test ($selection.Document.canonicalCaseIds.Count -eq 12) 'case type count mismatch'
        Assert-Test (@($resolved.GroupId | Select-Object -Unique).Count -eq 23) 'group IDs are not unique'
        Assert-Test ($selection.Document.candidatePlanSha256 -eq
            'f38e4d0cdeee79fbfe0f68876d5a6fb15bbcd92bd5a2e7cb8df9b524657a34fc') 'candidate plan SHA mismatch'
    }

    Invoke-SafetyTest 'X25519 M=3 and SHA-256 E=3 accounting' {
        $m3 = @($resolved | Where-Object { $_.GroupId -like '*runCountSensitivity*' })[0]
        $e1 = @($resolved | Where-Object { $_.GroupId -eq 'batch-e1-sha256' })[0]
        $e3 = @($resolved | Where-Object { $_.GroupId -eq 'batch-e3-sha256' })[0]
        Assert-Test ($m3.LogicalRuns -eq 3) 'X25519 M=3 must reserve three runs'
        Assert-Test ($e1.LogicalRuns -eq 1) 'E=1 must reserve one run'
        Assert-Test ($e3.LogicalRuns -eq 3 -and $e3.BatchShape.entries.Count -eq 3) `
            'E=3 must be one three-entry Batch with three logical runs'
    }

    Invoke-SafetyTest 'Duplicate selected group rejection' {
        $bad = $selection.Document | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $bad.groups[1].groupId = $bad.groups[0].groupId
        Assert-Throws {
            Resolve-M23Selection ([pscustomobject]@{ Document = $bad }) $plan
        } 'duplicate selection was accepted'
    }

    Invoke-SafetyTest 'Unknown row rejection' {
        $bad = $selection.Document | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $bad.groups[0].groupId = 'pilot-not-a-canonical-row'
        Assert-Throws {
            Resolve-M23Selection ([pscustomobject]@{ Document = $bad }) $plan
        } 'unknown row was accepted'
    }

    Invoke-SafetyTest 'Deferred row and deferred E-shape rejection' {
        $deferred = @($plan.rows | Where-Object { $_.status -eq 'deferred' })[0]
        $badRow = $selection.Document | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $badRow.groups[0].groupId = $deferred.rowId
        $badRow.groups[0].selector = [pscustomobject]@{
            caseId = $deferred.caseId
            inputBytes = $deferred.inputBytes
            iterationsPerRun = $deferred.iterationsPerRun
            probeKind = $deferred.probeKind
            repetition = $deferred.repetition
            role = $deferred.role
            runs = $deferred.runs
            samplingIntervalMilliseconds = $deferred.samplingIntervalMilliseconds
            status = $deferred.status
        }
        Assert-Throws {
            Resolve-M23Selection ([pscustomobject]@{ Document = $badRow }) $plan
        } 'deferred row was accepted'
        $badShape = $selection.Document | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $badShape.groups[19].groupId = 'batch-e10-sha256'
        $badShape.groups[19].selector.batchId = 'batch-e10-sha256'
        $badShape.groups[19].selector.entries = 10
        Assert-Throws {
            Resolve-M23Selection ([pscustomobject]@{ Document = $badShape }) $plan
        } 'deferred E=10 shape was accepted'
    }

    Invoke-SafetyTest 'Selection hash mismatch rejection' {
        $wrong = '0' * 64
        Assert-Test ($selection.Sha256 -cne $wrong) 'test fixture unexpectedly has wrong hash'
        Assert-Throws {
            Read-M23SelectionFile $selection.Path $wrong
        } 'selection hash guard did not reject mismatch'
        $changedPath = Join-Path $temporaryRoot 'changed-selection.json'
        $changed = $selection.Document | ConvertTo-Json -Depth 40
        $changed = $changed.Replace('"logicalWorkerRunCount": 27',
            '"logicalWorkerRunCount": 28')
        [System.IO.File]::WriteAllText(
            $changedPath, $changed, (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws {
            Read-M23SelectionFile $changedPath $script:M23PilotSelectionSha256
        } 'changed selected manifest was accepted under the reviewed hash'
    }

    Invoke-SafetyTest 'No GO and no-observation default gates' {
        Assert-Test ((Parse-M23SessionArguments @()).Mode -eq 'DryRun') `
            'no-option invocation is not the harmless dry-run'
        Assert-Throws {
            Parse-M23SessionArguments @('-ExecuteNext', '-Ordinal', '1')
        } 'ExecuteNext without complete GO arguments was accepted'
        Assert-Throws {
            Parse-M23SessionArguments @('-DryRun', '-DryRun')
        } 'duplicate command mode was accepted'
        Assert-Throws {
            Parse-M23SessionArguments @('-ExecuteNext','-Ordinal','1',
                '-Ordinal','2','-ArchiveRoot','D:\outside',
                '-ApprovedPlan','D:\outside\approved.json',
                '-ApprovedPlanSha256',('a' * 64),
                '-SelectionSha256',('b' * 64),
                '-ApprovalReference','TEST-REF','-IConfirmM232Go')
        } 'duplicate valued option was accepted'
        Assert-Throws {
            Parse-M23SessionArguments @('-DryRun', '-InspectLedger',
                '-ArchiveRoot', 'D:\outside')
        } 'conflicting command modes were accepted'
        Assert-Throws {
            Parse-M23SessionArguments @('-UnknownOption')
        } 'unknown option was accepted'
        Assert-Throws {
            Parse-M23SessionArguments @('-DryRun', '-ArchiveRoot', 'D:\outside')
        } 'DryRun accepted an incompatible archive option'
        Assert-Test (-not $selection.Document.measurementAuthorized) `
            'proposed selection unexpectedly authorizes measurement'
        Assert-Test ($selection.Document.approvalReferenceAllowlist.Count -eq 0) `
            'selection unexpectedly contains an approval reference'
        $before = $script:M23PilotChildLaunchCount
        $listingBefore = @(Get-ChildItem -LiteralPath $temporaryRoot -Force).Count
        $dryRunOutput = @(Invoke-M23PilotSession -Arguments @())
        $listingAfter = @(Get-ChildItem -LiteralPath $temporaryRoot -Force).Count
        Assert-Test ($script:M23PilotChildLaunchCount -eq $before) 'dry-run attempted child launch'
        Assert-Test ($listingBefore -eq $listingAfter) 'dry-run created an archive/output path'
        Assert-Test (($dryRunOutput -join "`n").Contains('RESULT: PASS - NO OBSERVATIONS')) `
            'dry-run did not report its non-observing result'
    }

    Invoke-SafetyTest 'Approved-plan hash, GO, and selection allowlist guards' {
        $approvalDirectory = Join-Path $temporaryRoot 'approval-tests'
        [System.IO.Directory]::CreateDirectory($approvalDirectory) | Out-Null
        $candidate = $plan
        $allowlisted = $selection.Document | ConvertTo-Json -Depth 40 | ConvertFrom-Json
        $allowlisted.approvalReferenceAllowlist = @('M23.2-GO-TEST-REFERENCE')
        $wrapper = [ordered]@{
            format = 'cryptobenchmark-m23-approved-pilot-plan'
            schemaVersion = 1
            candidatePlanSha256 = $script:M23PilotCandidatePlanSha256
            approvalStatus = 'GO'
            approvalReference = 'M23.2-GO-TEST-REFERENCE'
            approvedAtUtc = '2026-10-31T00:00:00.000Z'
            plan = $candidate
        }
        $goodPath = Join-Path $approvalDirectory 'approved-test.json'
        [System.IO.File]::WriteAllText(
            $goodPath,
            (ConvertTo-Json -InputObject $wrapper -Depth 50),
            (New-Object System.Text.UTF8Encoding($false)))
        $goodHash = Get-M23FileSha256 $goodPath
        $good = Read-M23ApprovedPlan $goodPath $goodHash `
            ([pscustomobject]@{ Document = $allowlisted }) $candidate
        Assert-Test ($good.Reference -eq 'M23.2-GO-TEST-REFERENCE') 'valid test wrapper rejected'
        Assert-Throws {
            Read-M23ApprovedPlan $goodPath ('0' * 64) `
                ([pscustomobject]@{ Document = $allowlisted }) $candidate
        } 'wrong wrapper SHA was accepted'
        $wrapper.approvalStatus = 'REVISE'
        $badGoPath = Join-Path $approvalDirectory 'non-go.json'
        [System.IO.File]::WriteAllText(
            $badGoPath,
            (ConvertTo-Json -InputObject $wrapper -Depth 50),
            (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws {
            Read-M23ApprovedPlan $badGoPath (Get-M23FileSha256 $badGoPath) `
                ([pscustomobject]@{ Document = $allowlisted }) $candidate
        } 'non-GO wrapper was accepted'
        $wrapper.approvalStatus = 'GO'
        $wrapper.candidatePlanSha256 = '0' * 64
        $badCandidatePath = Join-Path $approvalDirectory 'wrong-candidate.json'
        [System.IO.File]::WriteAllText(
            $badCandidatePath,
            (ConvertTo-Json -InputObject $wrapper -Depth 50),
            (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws {
            Read-M23ApprovedPlan $badCandidatePath (Get-M23FileSha256 $badCandidatePath) `
                ([pscustomobject]@{ Document = $allowlisted }) $candidate
        } 'wrong candidate-plan SHA was accepted'
        $wrapper.candidatePlanSha256 = $script:M23PilotCandidatePlanSha256
        $wrapper.approvalReference = 'SYNTHETIC-TEST-ONLY'
        $badReferencePath = Join-Path $approvalDirectory 'synthetic-reference.json'
        [System.IO.File]::WriteAllText(
            $badReferencePath,
            (ConvertTo-Json -InputObject $wrapper -Depth 50),
            (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws {
            Read-M23ApprovedPlan $badReferencePath (Get-M23FileSha256 $badReferencePath) `
                ([pscustomobject]@{ Document = $allowlisted }) $candidate
        } 'synthetic approval reference was accepted'
        $wrapper.approvalReference = 'OTHER-REVIEW'
        $badAllowlistPath = Join-Path $approvalDirectory 'wrong-allowlist.json'
        [System.IO.File]::WriteAllText(
            $badAllowlistPath,
            (ConvertTo-Json -InputObject $wrapper -Depth 50),
            (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws {
            Read-M23ApprovedPlan $badAllowlistPath (Get-M23FileSha256 $badAllowlistPath) `
                ([pscustomobject]@{ Document = $allowlisted }) $candidate
        } 'approval reference outside reviewed allowlist was accepted'
    }

    Invoke-SafetyTest 'Dirty Git and Debug build provenance rejection' {
        Assert-Throws {
            Assert-M23RepositoryState ([pscustomobject]@{
                Branch = 'feature/m23-runtime-calibration-eta-activation'
                Clean = $false
            })
        } 'dirty worktree was accepted'
        Assert-Throws {
            Assert-M23RepositoryState ([pscustomobject]@{
                Branch = 'main'
                Clean = $true
            })
        } 'wrong branch was accepted'
        Assert-Throws {
            Assert-M23BuildMatchesRepository `
                ([pscustomobject]@{
                    Branch = 'feature/m23-runtime-calibration-eta-activation'
                    Clean = $true
                    Head = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                }) `
                ([pscustomobject]@{
                    BuildInfoCommit = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    BuildType = 'Release'
                    ApplicationSha256 = 'a' * 64
                    WorkerSha256 = 'b' * 64
                })
        } 'Release BuildInfo commit mismatch was accepted'
        Assert-Throws {
            Assert-M23BuildMatchesRepository `
                ([pscustomobject]@{
                    Branch = 'feature/m23-runtime-calibration-eta-activation'
                    Clean = $true
                    Head = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                }) `
                ([pscustomobject]@{
                    BuildInfoCommit = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    BuildType = 'Debug'
                    ApplicationSha256 = 'a' * 64
                    WorkerSha256 = 'b' * 64
                })
        } 'Debug executable provenance was accepted'
        $cache = Join-Path $temporaryRoot 'debug-CMakeCache.txt'
        [System.IO.File]::WriteAllText($cache, "CMAKE_BUILD_TYPE:STRING=Debug`n")
        Assert-Throws { Assert-M23BuildCacheType $cache 'Release' } `
            'Debug cache was accepted as Release'
    }

    Invoke-SafetyTest 'External archive root and reparse/symlink rejection' {
        Assert-Throws {
            Assert-M23ExternalArchiveRoot $repositoryRoot $repositoryRoot
        } 'repository-local archive root was accepted'
        $repositoryParent = [System.IO.Directory]::GetParent(
            $repositoryRoot.TrimEnd('\')
        ).FullName
        Assert-Throws {
            Assert-M23ExternalArchiveRoot $repositoryParent $repositoryRoot
        } 'archive root containing the repository was accepted'
        Assert-Throws {
            Assert-M23ExternalArchiveRoot `
                (Join-Path $temporaryRoot 'missing-archive-root') $repositoryRoot
        } 'missing archive root was accepted'
        $outside = Join-Path $temporaryRoot 'archive-root'
        [System.IO.Directory]::CreateDirectory($outside) | Out-Null
        Assert-M23ExternalArchiveRoot $outside $repositoryRoot | Out-Null
        $junction = Join-Path $temporaryRoot 'archive-junction'
        New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
        Assert-Throws {
            Assert-M23ExternalArchiveRoot $junction $repositoryRoot
        } 'symlink/junction archive root was accepted'
    }

    Invoke-SafetyTest 'Local archive volume classification fails closed' {
        Assert-M23LocalArchiveVolumeForPath $temporaryRoot
        Assert-M23LocalArchiveVolume ([System.IO.DriveType]::Fixed) $true `
            ([long]$script:M23PilotResourceMinimumBytes)
        Assert-Throws {
            Assert-M23LocalArchiveVolume ([System.IO.DriveType]::Network) $true `
                ([long]$script:M23PilotResourceMinimumBytes)
        } 'mapped/network volume was accepted'
        Assert-Throws {
            Assert-M23LocalArchiveVolume ([System.IO.DriveType]::Unknown) $true `
                ([long]$script:M23PilotResourceMinimumBytes)
        } 'indeterminate drive type was accepted'
        Assert-Throws {
            Assert-M23LocalArchiveVolume ([System.IO.DriveType]::Fixed) $null `
                ([long]$script:M23PilotResourceMinimumBytes)
        } 'indeterminate volume readiness was accepted'
        Assert-Throws {
            Assert-M23LocalArchiveVolume ([System.IO.DriveType]::Fixed) $true $null
        } 'missing free-space information was accepted'
        Assert-Throws {
            Assert-M23LocalArchiveVolume ([System.IO.DriveType]::Fixed) $true `
                ([long]($script:M23PilotResourceMinimumBytes - 1))
        } 'insufficient archive free space was accepted'
    }

    Invoke-SafetyTest 'Successful evidence binds approval, result, and manifest' {
        $evidenceRoot = Join-Path $temporaryRoot 'evidence-integrity'
        [System.IO.Directory]::CreateDirectory($evidenceRoot) | Out-Null
        $group = $resolved[0]
        $head = (git -C $repositoryRoot rev-parse HEAD).Trim()
        $build = [pscustomobject]@{
            BuildInfoCommit = $head
            BuildType = 'Release'
            ApplicationSha256 = 'a' * 64
            WorkerSha256 = 'b' * 64
        }
        $approval = [pscustomobject]@{
            Sha256 = 'c' * 64
            Reference = 'SYNTHETIC-EVIDENCE-TEST'
        }
        $validPath = Join-Path $evidenceRoot 'valid'
        [System.IO.Directory]::CreateDirectory($validPath) | Out-Null
        Write-TestSyntheticPilotEvidence $validPath $group $approval $build ''
        Test-M23ChildEvidence $validPath $group $approval $build | Out-Null

        $wrongApprovalPath = Join-Path $evidenceRoot 'wrong-approved-plan'
        [System.IO.Directory]::CreateDirectory($wrongApprovalPath) | Out-Null
        Write-TestSyntheticPilotEvidence $wrongApprovalPath $group $approval `
            $build ('d' * 64)
        Assert-Throws {
            Test-M23ChildEvidence $wrongApprovalPath $group $approval $build
        } 'different syntactically valid approved-plan SHA was accepted'

        $corruptResultPath = Join-Path $evidenceRoot 'corrupt-result'
        [System.IO.Directory]::CreateDirectory($corruptResultPath) | Out-Null
        Write-TestSyntheticPilotEvidence $corruptResultPath $group $approval `
            $build '' -CorruptBatchResultAfterMarker
        Assert-Throws {
            Test-M23ChildEvidence $corruptResultPath $group $approval $build
        } 'modified batch result was accepted'

        $wrongManifestHashPath = Join-Path $evidenceRoot 'wrong-manifest-result-hash'
        [System.IO.Directory]::CreateDirectory($wrongManifestHashPath) | Out-Null
        Write-TestSyntheticPilotEvidence $wrongManifestHashPath $group $approval `
            $build '' -WrongBatchResultSha256
        Assert-Throws {
            Test-M23ChildEvidence $wrongManifestHashPath $group $approval $build
        } 'manifest with incorrect result SHA and updated marker was accepted'
    }

    Invoke-SafetyTest 'Exclusive ledger lock collision' {
        $lockPath = Join-Path $temporaryRoot 'lock-collision.lock'
        $first = New-Object System.IO.FileStream(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::ReadWrite)
        try {
            $first.Lock(0, 1)
            Assert-Throws { Enter-M23LedgerLock $lockPath | Out-Null } `
                'concurrent ledger lock was accepted'
        } finally {
            $first.Unlock(0, 1)
            $first.Dispose()
        }
    }

    Invoke-SafetyTest 'Interrupted reservation fails closed' {
        $ledgerPath = Join-Path $temporaryRoot 'interrupted-ledger.json'
        $first = $resolved[0]
        $entry = New-TestLedgerEntry 1 $first.GroupId $first.LogicalRuns 'reserved' 0
        $payload = New-M23LedgerPayload $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 '7daef7289cf80557c4c52936b68de47d659f23c3' @($entry)
        Write-M23AtomicBytes $ledgerPath (ConvertTo-M23LedgerBytes $payload)
        Assert-Throws {
            Read-M23Ledger $ledgerPath $selection.Sha256 `
                $script:M23PilotCandidatePlanSha256 `
                '7daef7289cf80557c4c52936b68de47d659f23c3' $resolved
        } 'reserved/interrupted ledger was accepted for retry/advance'
        $entry.status = 'quarantined'
        $payload = New-M23LedgerPayload $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 `
            '7daef7289cf80557c4c52936b68de47d659f23c3' @($entry) 1
        Write-M23AtomicBytes $ledgerPath (ConvertTo-M23LedgerBytes $payload)
        Assert-Throws {
            Read-M23Ledger $ledgerPath $selection.Sha256 `
                $script:M23PilotCandidatePlanSha256 `
                '7daef7289cf80557c4c52936b68de47d659f23c3' $resolved
        } 'quarantined group did not block automatic advance'
    }

    Invoke-SafetyTest 'Ledger checksum and quarantined archive manifest' {
        $ledgerPath = Join-Path $temporaryRoot 'checked-ledger.json'
        $first = $resolved[0]
        $entry = New-TestLedgerEntry 1 $first.GroupId $first.LogicalRuns 'completed' 1250
        $payload = New-M23LedgerPayload $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 `
            '7daef7289cf80557c4c52936b68de47d659f23c3' @($entry) 3
        Write-M23AtomicBytes $ledgerPath (ConvertTo-M23LedgerBytes $payload)
        $read = Read-M23Ledger $ledgerPath $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 `
            '7daef7289cf80557c4c52936b68de47d659f23c3' $resolved
        Assert-Test ($read.entries.Count -eq 1 -and $read.logicalRunsReserved -eq 1) `
            'valid atomic ledger did not round-trip'
        $envelope = [System.IO.File]::ReadAllText($ledgerPath) | ConvertFrom-Json
        $envelope.payloadSha256 = '0' * 64
        [System.IO.File]::WriteAllText(
            $ledgerPath,
            (ConvertTo-Json -InputObject $envelope -Compress),
            (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws {
            Read-M23Ledger $ledgerPath $selection.Sha256 `
                $script:M23PilotCandidatePlanSha256 `
                '7daef7289cf80557c4c52936b68de47d659f23c3' $resolved
        } 'edited ledger with a stale checksum was accepted'

        $evidenceDirectory = Join-Path $temporaryRoot 'quarantined-group'
        [System.IO.Directory]::CreateDirectory($evidenceDirectory) | Out-Null
        $rawPath = Join-Path $evidenceDirectory 'raw-failure.txt'
        [System.IO.File]::WriteAllText($rawPath, 'preserve synthetic failure bytes')
        $build = [pscustomobject]@{
            BuildInfoCommit = '7daef7289cf80557c4c52936b68de47d659f23c3'
            BuildType = 'Release'
            ApplicationSha256 = 'a' * 64
            WorkerSha256 = 'b' * 64
        }
        $approval = [pscustomobject]@{
            Sha256 = 'c' * 64
            Reference = 'SYNTHETIC TEST ONLY'
        }
        $manifestHash = Write-M23ArchiveManifest $evidenceDirectory `
            'QUARANTINED' 'synthetic-only failure fixture' $build $approval `
            $selection $first 321
        $archiveManifest = Get-Content `
            -LiteralPath (Join-Path $evidenceDirectory 'archive-manifest.json') -Raw |
            ConvertFrom-Json
        Assert-Test ($manifestHash -eq (Get-M23FileSha256 `
            (Join-Path $evidenceDirectory 'archive-manifest.json'))) `
            'archive manifest checksum was not returned accurately'
        Assert-Test (Test-Path -LiteralPath $rawPath) `
            'quarantined raw failure data was deleted'
        $rawRecord = @($archiveManifest.files |
            Where-Object { $_.path -eq 'raw-failure.txt' })
        Assert-Test ($rawRecord.Count -eq 1 -and
            $rawRecord[0].sha256 -eq (Get-M23FileSha256 $rawPath)) `
            'archive manifest omitted the raw failure checksum'
    }

    Invoke-SafetyTest 'Synthetic session lifecycle and quarantine stop' {
        try {
            $head = (git -C $repositoryRoot rev-parse HEAD).Trim()
            $approvedDocument = $selection.Document |
                ConvertTo-Json -Depth 40 | ConvertFrom-Json
            $approvedDocument.approvalReferenceAllowlist =
                @('M23.2-GO-TEST-REFERENCE')
            $testSelection = [pscustomobject]@{
                Document = $approvedDocument
                Sha256 = $selection.Sha256
            }
            $wrapper = [ordered]@{
                format = 'cryptobenchmark-m23-approved-pilot-plan'
                schemaVersion = 1
                candidatePlanSha256 = $script:M23PilotCandidatePlanSha256
                approvalStatus = 'GO'
                approvalReference = 'M23.2-GO-TEST-REFERENCE'
                approvedAtUtc = '2026-10-31T00:00:00.000Z'
                plan = $plan
            }
            $approvalPath = Join-Path $temporaryRoot 'lifecycle-approved.json'
            [System.IO.File]::WriteAllText(
                $approvalPath,
                (ConvertTo-Json -InputObject $wrapper -Depth 50),
                (New-Object System.Text.UTF8Encoding($false)))
            $approval = Read-M23ApprovedPlan $approvalPath `
                (Get-M23FileSha256 $approvalPath) $testSelection $plan
            $build = [pscustomobject]@{
                BuildInfoCommit = $head
                BuildType = 'Release'
                BuildRoot = $repositoryRoot
                Harness = 'synthetic-test-launcher'
                ApplicationSha256 = 'a' * 64
                WorkerSha256 = 'b' * 64
            }
            $state = [pscustomobject]@{ Head = $head }
            $group = $resolved[0]

            $successArchive = Join-Path $temporaryRoot 'synthetic-success-archive'
            [System.IO.Directory]::CreateDirectory($successArchive) | Out-Null
            $successArchive = Assert-M23ExternalArchiveRoot `
                $successArchive $repositoryRoot
            $script:M23PilotAnchorPathOverride =
                Join-Path $temporaryRoot 'synthetic-success-anchor.json'
            $successContext = [pscustomobject]@{
                ArchiveRoot = $successArchive
                LaunchCount = 0
                SawStartedReservation = $false
                LaunchObservation = ''
                CorruptResult = $false
            }
            $evidenceWriter = (Get-Command Write-TestSyntheticPilotEvidence).ScriptBlock
            $script:M23PilotTestLauncher = {
                param([int]$MaximumSeconds, [string]$OutputDirectory)
                $successContext.LaunchCount++
                $envelope = Get-Content -LiteralPath (
                    Join-Path $successContext.ArchiveRoot 'm23-pilot-ledger.json'
                ) -Raw | ConvertFrom-Json
                $payload = ([string]$envelope.payload) | ConvertFrom-Json
                $current = $payload.entries[$payload.entries.Count - 1]
                $successContext.LaunchObservation = '{0}|{1}|{2}|{3}|{4}' -f `
                    $MaximumSeconds, $payload.sequence, $current.status,
                    $current.reservedAtUtc, $current.startedAtUtc
                $successContext.SawStartedReservation =
                    ($MaximumSeconds -eq 900 -and
                     $payload.sequence -eq 2 -and
                     $current.status -ceq 'started' -and
                     -not [string]::IsNullOrWhiteSpace($current.reservedAtUtc) -and
                     -not [string]::IsNullOrWhiteSpace($current.startedAtUtc))
                & $evidenceWriter $OutputDirectory $group $approval $build ''
                return [pscustomobject]@{
                    ExitCode = 0
                    TimedOut = $false
                    TreeTerminated = $true
                    ElapsedMilliseconds = 25
                    Error = ''
                }
            }.GetNewClosure()
            $successOutput = @(Invoke-M23PilotReservedGroup 1 $successArchive `
                $testSelection $resolved $state $build $approval $group `
                (Get-M23GroupOutputPath $successArchive $group))
            $successLedgerPath = Join-Path $successArchive 'm23-pilot-ledger.json'
            $successLedger = Read-M23Ledger $successLedgerPath `
                $testSelection.Sha256 $script:M23PilotCandidatePlanSha256 `
                $head $resolved
            Assert-Test ($successContext.LaunchCount -eq 1 -and
                $successContext.SawStartedReservation) `
                ('fake child did not observe durable reservation and started state: ' +
                 $successContext.LaunchObservation)
            Assert-Test ($successLedger.entries[0].status -ceq 'completed' -and
                $successLedger.sequence -eq 3) `
                'successful lifecycle did not reach completed ledger state'
            $successOutputPath = Get-M23GroupOutputPath $successArchive $group
            $successArchiveManifest = Get-Content -LiteralPath (
                Join-Path $successOutputPath 'archive-manifest.json'
            ) -Raw | ConvertFrom-Json
            Assert-Test ($successArchiveManifest.disposition -ceq 'COMPLETED' -and
                $successLedger.entries[0].archiveManifestSha256 -eq
                    (Get-M23FileSha256 (
                        Join-Path $successOutputPath 'archive-manifest.json'
                    ))) 'completed evidence archive manifest was not bound into ledger'
            $inspection = @(Invoke-M23PilotInspect $successArchive) -join "`n"
            Assert-Test ($inspection.Contains('LEDGER=VALID') -and
                $inspection.Contains('ORDINAL=1 STATUS=completed')) `
                'read-only inspection rejected the completed synthetic lifecycle'

            $corruptArchive = Join-Path $temporaryRoot 'synthetic-corrupt-archive'
            [System.IO.Directory]::CreateDirectory($corruptArchive) | Out-Null
            $corruptArchive = Assert-M23ExternalArchiveRoot `
                $corruptArchive $repositoryRoot
            $script:M23PilotAnchorPathOverride =
                Join-Path $temporaryRoot 'synthetic-corrupt-anchor.json'
            $corruptContext = [pscustomobject]@{
                ArchiveRoot = $corruptArchive
                LaunchCount = 0
                CorruptResult = $true
            }
            $evidenceWriter = (Get-Command Write-TestSyntheticPilotEvidence).ScriptBlock
            $script:M23PilotTestLauncher = {
                param([int]$MaximumSeconds, [string]$OutputDirectory)
                $corruptContext.LaunchCount++
                & $evidenceWriter $OutputDirectory $group $approval $build '' `
                    -CorruptBatchResultAfterMarker
                return [pscustomobject]@{
                    ExitCode = 0
                    TimedOut = $false
                    TreeTerminated = $true
                    ElapsedMilliseconds = 30
                    Error = ''
                }
            }.GetNewClosure()
            Assert-Throws {
                Invoke-M23PilotReservedGroup 1 $corruptArchive `
                    $testSelection $resolved $state $build $approval $group `
                    (Get-M23GroupOutputPath $corruptArchive $group)
            } 'corrupted synthetic evidence was accepted as completed'
            $corruptLedgerPath = Join-Path $corruptArchive 'm23-pilot-ledger.json'
            $corruptEnvelope = Get-Content -LiteralPath $corruptLedgerPath -Raw |
                ConvertFrom-Json
            $corruptPayload = ([string]$corruptEnvelope.payload) | ConvertFrom-Json
            Assert-Test ($corruptContext.LaunchCount -eq 1 -and
                $corruptPayload.entries[0].status -ceq 'quarantined') `
                'corrupted child evidence was not retained as quarantined'
            $corruptOutputPath = Get-M23GroupOutputPath $corruptArchive $group
            Assert-Test ((Test-Path -LiteralPath (
                Join-Path $corruptOutputPath 'batch-result.json'
            )) -and (Test-Path -LiteralPath (
                Join-Path $corruptOutputPath 'archive-manifest.json'
            ))) 'quarantined raw result or archive manifest was not preserved'
            Assert-Throws {
                Invoke-M23PilotReservedGroup 2 $corruptArchive `
                    $testSelection $resolved $state $build $approval `
                    $resolved[1] (Get-M23GroupOutputPath $corruptArchive $resolved[1])
            } 'quarantined evidence did not block the next ordinal'
            Assert-Test ($corruptContext.LaunchCount -eq 1) `
                'quarantined evidence caused a second fake child launch'
            Assert-Throws {
                Invoke-M23PilotInspect $corruptArchive
            } 'read-only inspection accepted a quarantined ledger as advanceable'
        } finally {
            $script:M23PilotTestLauncher = $null
            $script:M23PilotAnchorPathOverride = $null
        }
    }

    Invoke-SafetyTest 'Pinned anchor detects ledger rollback' {
        $archiveRoot = Join-Path $temporaryRoot 'rollback-root'
        [System.IO.Directory]::CreateDirectory($archiveRoot) | Out-Null
        $ledgerPath = Join-Path $archiveRoot 'm23-pilot-ledger.json'
        $script:M23PilotAnchorPathOverride =
            Join-Path $temporaryRoot 'fixed-archive-anchor.json'
        $null = Assert-M23ArchiveRootBinding $archiveRoot `
            $selection.Sha256 -Create
        $sourceCommit = '7daef7289cf80557c4c52936b68de47d659f23c3'
        $anchorEntry = New-TestLedgerEntry 1 `
            $resolved[0].GroupId $resolved[0].LogicalRuns 'completed' 100
        $firstPayload = New-M23LedgerPayload $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 $sourceCommit @($anchorEntry) 1
        Write-M23LedgerState $ledgerPath $archiveRoot $selection.Sha256 $firstPayload
        $oldLedger = [System.IO.File]::ReadAllBytes($ledgerPath)
        $secondPayload = New-M23LedgerPayload $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 $sourceCommit @($anchorEntry) 2
        Write-M23LedgerState $ledgerPath $archiveRoot $selection.Sha256 $secondPayload
        [System.IO.File]::WriteAllBytes($ledgerPath, $oldLedger)
        $oldParsed = Read-M23Ledger $ledgerPath $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 $sourceCommit $resolved
        Assert-Throws {
            Assert-M23LedgerMatchesAnchor $ledgerPath $archiveRoot `
                $selection.Sha256 $oldParsed
        } 'restored earlier valid ledger was not detected against the external anchor'
        $script:M23PilotAnchorPathOverride = $null
    }

    Invoke-SafetyTest 'Thirty-run and four-hour cap boundaries' {
        $ledger30 = [pscustomobject]@{
            logicalRunsReserved = 27
            cumulativeActiveMilliseconds = 0
        }
        Assert-Test ((Get-M23RemainingReservation $ledger30 3) -eq 900) `
            '27 + 3 run boundary should be accepted'
        Assert-Throws { Get-M23RemainingReservation $ledger30 4 } `
            '30-run cap overrun was accepted'
        $ledger4h = [pscustomobject]@{
            logicalRunsReserved = 0
            cumulativeActiveMilliseconds = 14400000
        }
        Assert-Throws { Get-M23RemainingReservation $ledger4h 1 } `
            'four-hour boundary was accepted'
        $ledgerRemaining = [pscustomobject]@{
            logicalRunsReserved = 0
            cumulativeActiveMilliseconds = 13800000
        }
        Assert-Test ((Get-M23RemainingReservation $ledgerRemaining 1) -eq 600) `
            'per-child allowance did not use remaining total budget'
    }

    Invoke-SafetyTest 'Dry-run has no child, archive, ledger, or GO side effects' {
        $beforeSelection = Get-M23FileSha256 (Get-M23SelectionPath)
        $inspectRoot = Join-Path $temporaryRoot 'inspect-root'
        [System.IO.Directory]::CreateDirectory($inspectRoot) | Out-Null
        $beforeFiles = @(Get-ChildItem -LiteralPath $temporaryRoot -Recurse -Force |
            ForEach-Object { $_.FullName })
        $beforeLaunches = $script:M23PilotChildLaunchCount
        $output = @(Invoke-M23PilotSession -Arguments @('-DryRun'))
        $inspectOutput = @(Invoke-M23PilotInspect $inspectRoot)
        $afterFiles = @(Get-ChildItem -LiteralPath $temporaryRoot -Recurse -Force |
            ForEach-Object { $_.FullName })
        Assert-Test ($script:M23PilotChildLaunchCount -eq $beforeLaunches) `
            'dry-run changed child launch count'
        Assert-Test ((Get-M23FileSha256 (Get-M23SelectionPath)) -ceq $beforeSelection) `
            'dry-run changed selection file'
        Assert-Test (($beforeFiles -join '|') -ceq ($afterFiles -join '|')) `
            'dry-run created or removed files'
        Assert-Test (($output -join "`n").Contains('measurementAuthorized=false')) `
            'dry-run omitted NOT AUTHORIZED state'
        Assert-Test (($inspectOutput -join "`n").Contains('LEDGER=NOT_CREATED')) `
            'read-only inspection did not report an absent ledger'
        Assert-Test (-not ((Get-M23Selection).Document | ConvertTo-Json -Depth 40).Contains('"approvalStatus"')) `
            'selection file contains an approval/GO wrapper'
    }

    Invoke-SafetyTest 'Dummy process-tree hard timeout without benchmark worker' {
        $dummyDirectory = Join-Path $temporaryRoot 'dummy-process-tree'
        [System.IO.Directory]::CreateDirectory($dummyDirectory) | Out-Null
        $childPidPath = Join-Path $dummyDirectory 'grandchild.pid'
        $dummyPath = Join-Path $dummyDirectory 'dummy-parent.ps1'
        $dummyScript = @'
$child = New-Object System.Diagnostics.Process
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = Join-Path $PSHOME 'powershell.exe'
$start.Arguments = '-NoProfile -Command "Start-Sleep -Seconds 60"'
$start.UseShellExecute = $false
$child.StartInfo = $start
[void]$child.Start()
[System.IO.File]::WriteAllText($env:M23_DUMMY_CHILD_PID, [string]$child.Id)
Start-Sleep -Seconds 60
'@
        [System.IO.File]::WriteAllText(
            $dummyPath, $dummyScript, (New-Object System.Text.UTF8Encoding($false)))
        $env:M23_DUMMY_CHILD_PID = $childPidPath
        $powershellExe = Join-Path $PSHOME 'powershell.exe'
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File ' +
            (Quote-M23WindowsArgument $dummyPath)
        $result = [CryptoBenchmark.M23Pilot.JobProcess]::Run(
            $powershellExe, $arguments, $dummyDirectory,
            (Join-Path $dummyDirectory 'dummy.log'), 2500, 700)
        Assert-Test $result.TimedOut 'dummy child did not reach the simulated timeout'
        Assert-Test $result.TreeTerminated 'dummy process-tree termination was not verified'
        $deadline = [DateTime]::UtcNow.AddSeconds(3)
        while (-not (Test-Path -LiteralPath $childPidPath) -and
               [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 25
        }
        Assert-Test (Test-Path -LiteralPath $childPidPath) 'dummy descendant PID was not recorded'
        $grandchildPid = [int][System.IO.File]::ReadAllText($childPidPath)
        Assert-Test (Test-PidStopped $grandchildPid) 'dummy descendant survived job termination'
        Remove-Item Env:\M23_DUMMY_CHILD_PID -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item Env:\M23_DUMMY_CHILD_PID -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

if ($script:failedTests -gt 0) {
    throw "$($script:failedTests) non-observing safety test(s) failed; $($script:passedTests) passed"
}
Write-Output "Safety tests passed: $($script:passedTests)"
Write-Output 'RESULT: PASS - NO OBSERVATIONS'
