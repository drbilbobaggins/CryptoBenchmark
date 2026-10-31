Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:M23PilotCandidatePlanSha256 = 'f38e4d0cdeee79fbfe0f68876d5a6fb15bbcd92bd5a2e7cb8df9b524657a34fc'
$script:M23PilotSelectionSha256 = '0c62c74be9a33143011a9dbe3cf4924df28e261dc0d1cc1e8167a188ee4160bf'
$script:M23PilotMaximumGroups = 23
$script:M23PilotMaximumLogicalRuns = 30
$script:M23PilotMaximumWallSeconds = 14400
$script:M23PilotMaximumChildSeconds = 900
$script:M23PilotResourceMinimumBytes = 536870912
$script:M23PilotApprovalAllowlist = @()
$script:M23PilotChildLaunchCount = 0
$script:M23PilotTestMode = $false
$script:M23PilotTestLauncher = $null
$script:M23PilotTestEnvironment = $null
$script:M23PilotAnchorPathOverride = $null

function Initialize-M23JobProcessType {
if (-not ('CryptoBenchmark.M23Pilot.JobProcess' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoBenchmark.M23Pilot
{
    public sealed class ChildResult
    {
        public int ExitCode;
        public bool TimedOut;
        public bool TreeTerminated;
        public long ElapsedMilliseconds;
        public string Error;
    }

    public static class JobProcess
    {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 258;
        private const uint WAIT_FAILED = 0xffffffff;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 1;
        private const uint CREATE_ALWAYS = 2;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
        private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXTENDED_LIMIT_INFORMATION
        {
            public BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job, uint infoClass, IntPtr info, uint infoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job, uint infoClass, IntPtr info, uint infoLength, out uint returned);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreateProcess(
            string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment,
            string currentDirectory, ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(
            string existingName, string newName, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectory(string path, IntPtr securityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string fileName, uint desiredAccess, uint shareMode,
            IntPtr securityAttributes, uint creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        private static Exception LastError(string operation)
        {
            return new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        private static uint RemainingMilliseconds(Stopwatch timer, int maximumMilliseconds)
        {
            long remaining = maximumMilliseconds - timer.ElapsedMilliseconds;
            return (uint)Math.Max(0, Math.Min(UInt32.MaxValue, remaining));
        }

        private static uint ActiveProcesses(IntPtr job)
        {
            int size = Marshal.SizeOf(typeof(BASIC_ACCOUNTING_INFORMATION));
            IntPtr memory = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!QueryInformationJobObject(
                    job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                    memory, (uint)size, out returned))
                    throw LastError("QueryInformationJobObject");
                return Marshal.PtrToStructure<BASIC_ACCOUNTING_INFORMATION>(memory)
                    .ActiveProcesses;
            }
            finally { Marshal.FreeHGlobal(memory); }
        }

        public static void AtomicReplaceDurable(string source, string destination)
        {
            if (!MoveFileEx(source, destination,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw LastError("MoveFileEx atomic durable replacement");
        }

        public static void CreateDirectoryExclusive(string path)
        {
            if (!CreateDirectory(path, IntPtr.Zero))
                throw LastError("CreateDirectory exclusive output path");
        }

        private static string Quote(string value)
        {
            if (value.Length == 0) return "\"\"";
            if (value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
                return value;
            StringBuilder result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"')
                {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('"');
                    slashes = 0;
                    continue;
                }
                result.Append('\\', slashes);
                slashes = 0;
                result.Append(c);
            }
            result.Append('\\', slashes * 2);
            result.Append('"');
            return result.ToString();
        }

        public static ChildResult Run(
            string executable, string arguments, string workingDirectory,
            string logPath, int maximumMilliseconds, int cleanupGraceMilliseconds)
        {
            Stopwatch timer = Stopwatch.StartNew();
            IntPtr job = IntPtr.Zero;
            IntPtr log = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            bool processCreated = false;
            ChildResult result = new ChildResult();
            try
            {
                job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) throw LastError("CreateJobObject");
                EXTENDED_LIMIT_INFORMATION limits = new EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                int limitSize = Marshal.SizeOf(typeof(EXTENDED_LIMIT_INFORMATION));
                IntPtr limitMemory = Marshal.AllocHGlobal(limitSize);
                try
                {
                    Marshal.StructureToPtr(limits, limitMemory, false);
                    if (!SetInformationJobObject(
                        job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                        limitMemory, (uint)limitSize))
                        throw LastError("SetInformationJobObject");
                }
                finally { Marshal.FreeHGlobal(limitMemory); }

                SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
                security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                security.bInheritHandle = true;
                IntPtr securityMemory = Marshal.AllocHGlobal(security.nLength);
                try
                {
                    Marshal.StructureToPtr(security, securityMemory, false);
                    log = CreateFile(logPath, GENERIC_WRITE, FILE_SHARE_READ,
                        securityMemory, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                }
                finally { Marshal.FreeHGlobal(securityMemory); }
                if (log == new IntPtr(-1)) throw LastError("CreateFile child log");
                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startup.dwFlags = STARTF_USESTDHANDLES;
                startup.hStdInput = IntPtr.Zero;
                startup.hStdOutput = log;
                startup.hStdError = log;
                StringBuilder command = new StringBuilder(
                    Quote(executable) + " " + arguments);
                if (!CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero,
                    true, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero,
                    workingDirectory, ref startup, out process))
                    throw LastError("CreateProcess suspended child");
                processCreated = true;

                if (!AssignProcessToJobObject(job, process.hProcess))
                {
                    TerminateProcess(process.hProcess, 1);
                    WaitForSingleObject(
                        process.hProcess, RemainingMilliseconds(timer, maximumMilliseconds));
                    throw LastError("AssignProcessToJobObject");
                }
                if (timer.ElapsedMilliseconds >= maximumMilliseconds)
                {
                    TerminateJobObject(job, 1);
                    WaitForSingleObject(process.hProcess, 5000);
                    throw new TimeoutException(
                        "Process setup consumed the complete reserved hard bound before resume");
                }
                if (ResumeThread(process.hThread) == 0xffffffff)
                {
                    TerminateJobObject(job, 1);
                    WaitForSingleObject(
                        process.hProcess, RemainingMilliseconds(timer, maximumMilliseconds));
                    throw LastError("ResumeThread");
                }
                CloseHandle(process.hThread);
                process.hThread = IntPtr.Zero;

                int grace = Math.Min(cleanupGraceMilliseconds,
                    Math.Max(25, maximumMilliseconds / 20));
                int remaining = Math.Max(0,
                    maximumMilliseconds - (int)timer.ElapsedMilliseconds);
                grace = Math.Min(grace, remaining);
                int workWait = Math.Max(0, remaining - grace);
                uint wait = WaitForSingleObject(process.hProcess, (uint)workWait);
                if (wait == WAIT_OBJECT_0)
                {
                    uint code;
                    if (!GetExitCodeProcess(process.hProcess, out code))
                        throw LastError("GetExitCodeProcess");
                    result.ExitCode = unchecked((int)code);
                    uint active = ActiveProcesses(job);
                    if (active != 0)
                    {
                        result.Error = "Child process exited while descendants remained active";
                        TerminateJobObject(job, 1);
                        uint cleanupWait = WaitForSingleObject(
                            process.hProcess, (uint)grace);
                        result.TreeTerminated =
                            cleanupWait == WAIT_OBJECT_0 && ActiveProcesses(job) == 0;
                        if (!result.TreeTerminated)
                            result.Error = "Child process tree remained active after normal root exit";
                    }
                    else result.TreeTerminated = true;
                }
                else if (wait == WAIT_TIMEOUT)
                {
                    result.TimedOut = true;
                    if (!TerminateJobObject(job, 124))
                        throw LastError("TerminateJobObject timeout");
                    uint cleanupWait = WaitForSingleObject(process.hProcess, (uint)grace);
                    result.TreeTerminated =
                        cleanupWait == WAIT_OBJECT_0 && ActiveProcesses(job) == 0;
                    if (!result.TreeTerminated)
                        result.Error = "Process-tree termination was not verified within the reserved hard bound";
                }
                else if (wait == WAIT_FAILED) throw LastError("WaitForSingleObject child");
                else throw new InvalidOperationException("Unexpected child wait result");
            }
            catch (Exception error)
            {
                result.Error = error.ToString();
                if (job != IntPtr.Zero)
                {
                    try { TerminateJobObject(job, 1); } catch { }
                }
                else if (processCreated && process.hProcess != IntPtr.Zero)
                {
                    try { TerminateProcess(process.hProcess, 1); } catch { }
                }
                if (processCreated && process.hProcess != IntPtr.Zero)
                {
                    try {
                        WaitForSingleObject(
                            process.hProcess,
                            RemainingMilliseconds(timer, maximumMilliseconds));
                    } catch { }
                }
            }
            finally
            {
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                if (log != IntPtr.Zero && log != new IntPtr(-1)) CloseHandle(log);
                if (job != IntPtr.Zero) CloseHandle(job);
                timer.Stop();
                result.ElapsedMilliseconds = timer.ElapsedMilliseconds;
            }
            return result;
        }
    }
}
'@
}
}

function Get-M23RepoRoot {
    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
}

function Get-M23SelectionPath {
    return [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot 'm23-pilot-selection-v1.json'))
}

function Get-M23ArchiveAnchorPath {
    if ($script:M23PilotTestMode -and
        -not [string]::IsNullOrWhiteSpace($script:M23PilotAnchorPathOverride)) {
        return [System.IO.Path]::GetFullPath($script:M23PilotAnchorPathOverride)
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is unavailable; a fixed cross-invocation archive anchor cannot be maintained'
    }
    return Join-Path $env:LOCALAPPDATA 'CryptoBenchmark\M23.2\archive-root.json'
}

function Read-M23SelectionFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $path = [System.IO.Path]::GetFullPath($Path)
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $text = $encoding.GetString($bytes)
    $document = $text | ConvertFrom-Json
    $sha256 = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    ) -replace '-', '').ToLowerInvariant()
    if ($sha256 -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Selection file differs from its reviewed pinned SHA-256'
    }
    return [pscustomobject]@{
        Document = $document
        Bytes = $bytes
        Sha256 = $sha256
        Path = $path
    }
}

function Get-M23Selection {
    return Read-M23SelectionFile (Get-M23SelectionPath) `
        $script:M23PilotSelectionSha256
}

function Get-M23CanonicalJson {
    param([Parameter(Mandatory = $true)][AllowNull()]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) {
        return (ConvertTo-Json -InputObject $Value -Compress)
    }
    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($key in @($Value.Keys | Sort-Object -Culture en-US)) {
            $parts.Add((ConvertTo-Json -InputObject ([string]$key) -Compress) +
                ':' + (Get-M23CanonicalJson -Value $Value[$key]))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($property in @($Value.PSObject.Properties | Sort-Object -Property Name -Culture en-US)) {
            $parts.Add((ConvertTo-Json -InputObject $property.Name -Compress) +
                ':' + (Get-M23CanonicalJson -Value $property.Value))
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Array]) {
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $parts.Add((Get-M23CanonicalJson -Value $item))
        }
        return '[' + ($parts -join ',') + ']'
    }
    if ($Value -is [System.ValueType]) {
        return (ConvertTo-Json -InputObject $Value -Compress)
    }
    throw "Unsupported JSON value type: $($Value.GetType().FullName)"
}

function Invoke-M23HarnessDryRun {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessPath,
        [Parameter(Mandatory = $true)][string]$ExpectedPlanSha256
    )
    $output = @(& $HarnessPath '--dry-run-pilot-plan')
    if ($LASTEXITCODE -ne 0) {
        throw "Candidate-plan dry-run failed with exit code $LASTEXITCODE"
    }
    $report = ($output -join "`n") | ConvertFrom-Json
    if ($report.reportLabel -ne 'DRY RUN - NO OBSERVATIONS' -or
        $report.measurementAuthorized -ne $false -or
        $report.status -ne 'CANDIDATE_ONLY_NOT_AUTHORIZED' -or
        $report.pilotPlanSha256 -ne $ExpectedPlanSha256) {
        throw 'Harness dry-run did not return the frozen unauthorized candidate plan'
    }
    return $report
}

function Resolve-M23Selection {
    param(
        [Parameter(Mandatory = $true)]$Selection,
        [Parameter(Mandatory = $true)]$CandidatePlan
    )

    $document = $Selection.Document
    if ($document.format -ne 'cryptobenchmark-m23-pilot-selection' -or
        $document.schemaVersion -ne 1 -or
        $document.status -ne 'PROPOSED_NOT_APPROVED' -or
        $document.measurementAuthorized -ne $false -or
        $document.candidatePlanSha256 -ne $script:M23PilotCandidatePlanSha256 -or
        $document.proposedGroupCount -ne 23 -or
        $document.logicalWorkerRunCount -ne 27 -or
        $document.reservedContingencyLogicalRuns -ne 3 -or
        $document.totalBudgetSeconds -ne 14400 -or
        $document.maximumChildSeconds -ne 900) {
        throw 'Selection file header, authorization, identity, or cap is invalid'
    }
    $groups = @($document.groups)
    if ($groups.Count -ne 23) { throw 'Selection must contain exactly 23 groups' }
    if ($document.canonicalCaseIds.Count -ne 12) {
        throw 'Selection must contain exactly 12 canonical case types'
    }
    if (@($groups | ForEach-Object { $_.ordinal } | Select-Object -Unique).Count -ne 23) {
        throw 'Selection contains duplicate ordinals'
    }
    for ($i = 0; $i -lt $groups.Count; $i++) {
        if ($groups[$i].ordinal -ne ($i + 1)) {
            throw 'Selection ordinals must be contiguous and in proposed order'
        }
    }

    $rows = @($CandidatePlan.rows)
    $shapes = @($CandidatePlan.batchShapes)
    $resolved = New-Object System.Collections.Generic.List[object]
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $caseIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    [long]$logicalRuns = 0
    foreach ($group in $groups) {
        if (-not $ids.Add([string]$group.groupId)) {
            throw "Duplicate selected group identity: $($group.groupId)"
        }
        if ($group.type -eq 'row') {
            $selector = $group.selector
            $matches = @($rows | Where-Object {
                $sameSize = if ($null -eq $selector.inputBytes) {
                    $null -eq $_.inputBytes
                } else {
                    [string]$_.inputBytes -ceq [string]$selector.inputBytes
                }
                ([string]$_.caseId -ceq [string]$selector.caseId) -and
                ([string]$_.role -ceq [string]$selector.role) -and
                ([string]$_.probeKind -ceq [string]$selector.probeKind) -and
                $sameSize -and
                ([string]$_.iterationsPerRun -ceq [string]$selector.iterationsPerRun) -and
                ([int]$_.runs -eq [int]$selector.runs) -and
                ([int]$_.samplingIntervalMilliseconds -eq [int]$selector.samplingIntervalMilliseconds) -and
                ([int]$_.repetition -eq [int]$selector.repetition) -and
                ([string]$_.status -ceq [string]$selector.status)
            })
            if ($selector.status -ne 'candidate' -or $matches.Count -ne 1) {
                throw "Selected row is unknown, deferred, or ambiguous at ordinal $($group.ordinal)"
            }
            if ($matches[0].rowId -cne $group.groupId) {
                throw "Selected canonical row ID mismatch at ordinal $($group.ordinal)"
            }
            if ([int]$group.logicalWorkerRuns -ne [int]$selector.runs) {
                throw "Logical run accounting mismatch at ordinal $($group.ordinal)"
            }
            [void]$caseIds.Add([string]$selector.caseId)
            $logicalRuns += [int]$selector.runs
            $resolved.Add([pscustomobject]@{
                Ordinal = [int]$group.ordinal
                GroupId = [string]$group.groupId
                Type = 'row'
                Selector = $selector
                LogicalRuns = [int]$selector.runs
                PlanRow = $matches[0]
            })
        } elseif ($group.type -eq 'batch') {
            $selector = $group.selector
            $matches = @($shapes | Where-Object {
                $_.batchId -ceq [string]$selector.batchId -and
                $_.status -ceq 'candidate' -and
                $_.batchId -ceq [string]$group.groupId -and
                [int]$_.entries.Count -eq [int]$selector.entries -and
                [string]$_.inputBytes -ceq [string]$selector.inputBytes -and
                [string]$_.iterationsPerRun -ceq [string]$selector.iterationsPerRun -and
                [int]$_.runs -eq [int]$selector.runsPerEntry -and
                [int]$_.samplingIntervalMilliseconds -eq [int]$selector.samplingIntervalMilliseconds
            })
            if ($selector.status -ne 'candidate' -or $matches.Count -ne 1 -or
                [string]$selector.role -cne 'batchShape' -or
                [string]$selector.probeKind -cne 'batchEntryCount' -or
                [int]$selector.repetition -ne 1) {
                throw "Selected Batch shape is unknown, deferred, or ambiguous at ordinal $($group.ordinal)"
            }
            if ($matches[0].entries.Count -gt 3 -or
                [int]$group.logicalWorkerRuns -ne
                    ([int]$matches[0].entries.Count * [int]$matches[0].runs)) {
                throw "Batch logical-run accounting mismatch at ordinal $($group.ordinal)"
            }
            if ($selector.caseId -cne 'sha256/hash/hashXof' -or
                @($matches[0].entries | Where-Object {
                    $_.caseId -cne $selector.caseId
                }).Count -ne 0) {
                throw "Batch entries differ from selected canonical case at ordinal $($group.ordinal)"
            }
            foreach ($entry in $matches[0].entries) {
                [void]$caseIds.Add([string]$entry.caseId)
            }
            $logicalRuns += [int]$group.logicalWorkerRuns
            $resolved.Add([pscustomobject]@{
                Ordinal = [int]$group.ordinal
                GroupId = [string]$group.groupId
                Type = 'batch'
                Selector = $selector
                LogicalRuns = [int]$group.logicalWorkerRuns
                BatchShape = $matches[0]
            })
        } else {
            throw "Unknown group type at ordinal $($group.ordinal)"
        }
    }
    if ($logicalRuns -ne 27 -or $caseIds.Count -ne 12) {
        throw "Selection totals mismatch: groups=$($groups.Count), runs=$logicalRuns, cases=$($caseIds.Count)"
    }
    foreach ($caseId in $document.canonicalCaseIds) {
        if (-not $caseIds.Contains([string]$caseId)) {
            throw "Selection is missing a canonical case: $caseId"
        }
    }
    $deferredIds = @($CandidatePlan.rows | Where-Object { $_.status -eq 'deferred' } |
        ForEach-Object { $_.rowId })
    foreach ($group in $resolved) {
        if ($deferredIds -contains $group.GroupId) {
            throw "Deferred candidate row selected: $($group.GroupId)"
        }
        if ($group.Type -eq 'batch' -and
            $group.BatchShape.batchId -notin @('batch-e1-sha256', 'batch-e3-sha256')) {
            throw "Unapproved Batch shape selected: $($group.GroupId)"
        }
    }
    return ,$resolved.ToArray()
}

function Get-M23RepositoryState {
    param([string]$RepositoryRoot)
    $branch = (& git -C $RepositoryRoot branch --show-current).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Git branch' }
    $head = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Git HEAD' }
    $status = @(& git -C $RepositoryRoot status --porcelain --untracked-files=normal)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read Git worktree status' }
    return [pscustomobject]@{
        Branch = $branch
        Head = $head
        Clean = ($status.Count -eq 0)
    }
}

function Get-M23BuildProvenance {
    param([string]$RepositoryRoot)
    $buildRoot = Join-Path $RepositoryRoot 'build-m23-release'
    $cachePath = Join-Path $buildRoot 'CMakeCache.txt'
    $buildInfoPath = Join-Path $buildRoot 'src\application\generated\cryptobench\application\BuildInfo.h'
    $harness = Join-Path $buildRoot 'test-runtime\CryptoBenchmarkM23CalibrationTests.exe'
    $application = Join-Path $buildRoot 'bin\CryptoBenchmark.exe'
    $worker = Join-Path $buildRoot 'bin\CryptoBenchmarkWorker.exe'
    foreach ($path in @($cachePath, $buildInfoPath, $harness, $application, $worker)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required Release build artifact is missing: $path"
        }
        Assert-M23NoReparsePath $path | Out-Null
    }
    Assert-M23BuildCacheType $cachePath 'Release'
    $buildInfo = [System.IO.File]::ReadAllText($buildInfoPath)
    $commitMatch = [regex]::Match($buildInfo, 'gitCommit\s*=\s*"([0-9a-f]{40})"')
    $typeMatch = [regex]::Match($buildInfo, 'buildType\s*=\s*"([^"]+)"')
    if (-not $commitMatch.Success -or -not $typeMatch.Success -or
        $typeMatch.Groups[1].Value -cne 'Release') {
        throw 'Generated Release BuildInfo is malformed'
    }
    return [pscustomobject]@{
        BuildRoot = $buildRoot
        BuildInfoCommit = $commitMatch.Groups[1].Value
        BuildType = $typeMatch.Groups[1].Value
        Harness = $harness
        Application = $application
        Worker = $worker
        ApplicationSha256 = Get-M23FileSha256 $application
        WorkerSha256 = Get-M23FileSha256 $worker
    }
}

function Assert-M23RepositoryState {
    param([Parameter(Mandatory = $true)]$State)
    if ($State.Branch -cne 'feature/m23-runtime-calibration-eta-activation') {
        throw 'Execution requires feature/m23-runtime-calibration-eta-activation'
    }
    if (-not $State.Clean) { throw 'Execution requires a clean Git worktree' }
}

function Assert-M23BuildMatchesRepository {
    param($State, $Build)
    Assert-M23RepositoryState $State
    if ($Build.BuildType -cne 'Release' -or
        $State.Head -cne $Build.BuildInfoCommit) {
        throw 'Release BuildInfo commit/type does not match clean Git HEAD'
    }
    foreach ($hash in @($Build.ApplicationSha256, $Build.WorkerSha256)) {
        if ([string]$hash -notmatch '^[0-9a-f]{64}$') {
            throw 'Release application/worker SHA-256 provenance is malformed'
        }
    }
}

function Get-M23RemainingReservation {
    param(
        [Parameter(Mandatory = $true)]$Ledger,
        [Parameter(Mandatory = $true)][int]$LogicalRunsToReserve
    )
    if ($LogicalRunsToReserve -lt 1 -or
        ([long]$Ledger.logicalRunsReserved + $LogicalRunsToReserve) -gt
            $script:M23PilotMaximumLogicalRuns) {
        throw 'Thirty-logical-run cumulative cap would be exceeded'
    }
    $remainingMilliseconds = [long]$script:M23PilotMaximumWallSeconds * 1000 -
        [long]$Ledger.cumulativeActiveMilliseconds
    if ($remainingMilliseconds -le 0) {
        throw 'Four-hour cumulative active-launch cap is exhausted'
    }
    $seconds = [Math]::Min(
        $script:M23PilotMaximumChildSeconds,
        [int][Math]::Floor($remainingMilliseconds / 1000.0))
    if ($seconds -lt 1) { throw 'Less than one second remains in the total cap' }
    return $seconds
}

function Assert-M23BuildCacheType {
    param(
        [Parameter(Mandatory = $true)][string]$CachePath,
        [Parameter(Mandatory = $true)][string]$ExpectedType
    )
    $cacheLines = [System.IO.File]::ReadAllLines($CachePath)
    if (@($cacheLines | Where-Object {
        $_ -ceq ('CMAKE_BUILD_TYPE:STRING=' + $ExpectedType)
    }).Count -ne 1) {
        throw "CMakeCache must report $ExpectedType"
    }
}

function Get-M23FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
}

function Assert-M23NoReparsePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    $current = $root
    $relative = $full.Substring($root.Length)
    foreach ($part in ($relative -split '[\\/]')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse-point/symlink path is not accepted: $current"
            }
        }
    }
    return $full
}

function Assert-M23ExternalArchiveRoot {
    param(
        [Parameter(Mandatory = $true)][string]$ArchiveRoot,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )
    $full = Assert-M23NoReparsePath $ArchiveRoot
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw 'Archive root must be an existing operator-created directory'
    }
    $repo = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\') + '\'
    $candidate = $full.TrimEnd('\') + '\'
    if ($candidate.StartsWith($repo, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate -ieq $repo -or
        $repo.StartsWith($candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Archive root must be outside the repository and all build/source paths'
    }
    return $full
}

function Assert-M23ArchiveRootBinding {
    param(
        [Parameter(Mandatory = $true)][string]$ArchiveRoot,
        [Parameter(Mandatory = $true)][string]$SelectionSha256,
        [switch]$Create
    )
    $anchorPath = Get-M23ArchiveAnchorPath
    $anchorDirectory = [System.IO.Path]::GetDirectoryName($anchorPath)
    if (Test-Path -LiteralPath $anchorDirectory -PathType Container) {
        Assert-M23NoReparsePath $anchorDirectory | Out-Null
    }
    if (Test-Path -LiteralPath $anchorPath -PathType Leaf) {
        Assert-M23NoReparsePath $anchorPath | Out-Null
        $anchorBytes = [System.IO.File]::ReadAllBytes($anchorPath)
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $anchor = $strictUtf8.GetString($anchorBytes) | ConvertFrom-Json
        if ($anchor.format -cne 'cryptobenchmark-m23-archive-root-anchor' -or
            [int]$anchor.schemaVersion -ne 1 -or
            [string]$anchor.archiveRoot -cne [System.IO.Path]::GetFullPath($ArchiveRoot) -or
            [string]$anchor.selectionSha256 -cne $SelectionSha256 -or
            [string]$anchor.ledgerSha256 -notmatch '^(|[0-9a-f]{64})$' -or
            [long]$anchor.ledgerSequence -lt 0) {
            throw 'Selected archive root/selection differs from the fixed ledger anchor'
        }
        return $anchor
    }
    if (-not $Create) {
        throw 'Archive-root anchor is missing; read-only inspection will not create it'
    }
    if (Test-Path -LiteralPath (Join-Path $ArchiveRoot 'm23-pilot-ledger.json')) {
        throw 'Ledger exists without its archive-root anchor; manual reconciliation required'
    }
    [System.IO.Directory]::CreateDirectory($anchorDirectory) | Out-Null
    Assert-M23NoReparsePath $anchorDirectory | Out-Null
    $payload = [ordered]@{
        format = 'cryptobenchmark-m23-archive-root-anchor'
        schemaVersion = 1
        archiveRoot = [System.IO.Path]::GetFullPath($ArchiveRoot)
        selectionSha256 = $SelectionSha256
        ledgerSequence = [long]0
        ledgerSha256 = ''
        boundAtUtc = [DateTime]::UtcNow.ToString('o')
        updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $payload -Compress))
    Write-M23AtomicBytes $anchorPath $bytes
    return ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
}

function Write-M23LedgerState {
    param(
        [Parameter(Mandatory = $true)][string]$LedgerPath,
        [Parameter(Mandatory = $true)][string]$ArchiveRoot,
        [Parameter(Mandatory = $true)][string]$SelectionSha256,
        [Parameter(Mandatory = $true)]$Payload
    )
    $bytes = ConvertTo-M23LedgerBytes $Payload
    Write-M23AtomicBytes $LedgerPath $bytes
    $anchor = Assert-M23ArchiveRootBinding $ArchiveRoot $SelectionSha256
    if ([long]$Payload.sequence -ne ([long]$anchor.ledgerSequence + 1)) {
        throw 'Ledger sequence does not advance exactly once from its pinned anchor'
    }
    $anchor.ledgerSequence = [long]$Payload.sequence
    $anchor.ledgerSha256 = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    ) -replace '-', '').ToLowerInvariant()
    $anchor.updatedAtUtc = [DateTime]::UtcNow.ToString('o')
    $anchorBytes = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $anchor -Compress))
    Write-M23AtomicBytes (Get-M23ArchiveAnchorPath) $anchorBytes
}

function Assert-M23LedgerMatchesAnchor {
    param(
        [string]$LedgerPath,
        [string]$ArchiveRoot,
        [string]$SelectionSha256,
        $Payload
    )
    $anchor = Assert-M23ArchiveRootBinding $ArchiveRoot $SelectionSha256
    if (Test-Path -LiteralPath $LedgerPath -PathType Leaf) {
        $actual = Get-M23FileSha256 $LedgerPath
        if ($actual -cne [string]$anchor.ledgerSha256 -or
            [long]$Payload.sequence -ne [long]$anchor.ledgerSequence) {
            throw 'Ledger rollback or anchor mismatch detected; manual reconciliation required'
        }
    } elseif ([long]$anchor.ledgerSequence -ne 0 -or
              -not [string]::IsNullOrEmpty([string]$anchor.ledgerSha256) -or
              [long]$Payload.sequence -ne 0) {
        throw 'Ledger disappeared after a reservation; manual reconciliation required'
    }
}

function Read-M23ApprovedPlan {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)]$Selection,
        [Parameter(Mandatory = $true)]$CandidatePlan
    )
    $full = Assert-M23NoReparsePath $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw 'Approved-plan file is missing'
    }
    $bytes = [System.IO.File]::ReadAllBytes($full)
    if ($bytes.Length -gt 1048576) { throw 'Approved-plan file exceeds 1 MiB' }
    $sha = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    ) -replace '-', '').ToLowerInvariant()
    if ($sha -cne $ExpectedSha256.ToLowerInvariant()) {
        throw 'Approved-plan exact-byte SHA-256 does not match'
    }
    $encoding = New-Object System.Text.UTF8Encoding($false, $true)
    $wrapper = $encoding.GetString($bytes) | ConvertFrom-Json
    $expectedKeys = @('format','schemaVersion','candidatePlanSha256',
        'approvalStatus','approvalReference','approvedAtUtc','plan')
    $keys = @($wrapper.PSObject.Properties | ForEach-Object { $_.Name })
    if ($keys.Count -ne 7 -or
        @($keys | Where-Object { $_ -notin $expectedKeys }).Count -ne 0 -or
        @($expectedKeys | Where-Object { $_ -notin $keys }).Count -ne 0) {
        throw 'Approved-plan wrapper must contain exactly the seven reviewed fields'
    }
    if ($wrapper.format -cne 'cryptobenchmark-m23-approved-pilot-plan' -or
        [int]$wrapper.schemaVersion -ne 1 -or
        $wrapper.approvalStatus -cne 'GO' -or
        $wrapper.candidatePlanSha256 -cne $script:M23PilotCandidatePlanSha256) {
        throw 'Approved-plan format, version, GO, or candidate-plan hash is invalid'
    }
    if ((Get-M23CanonicalJson $wrapper.plan) -cne
        (Get-M23CanonicalJson $CandidatePlan)) {
        throw 'Approved-plan rows differ from the frozen canonical candidate plan'
    }
    $reference = ([string]$wrapper.approvalReference).Trim()
    if ([string]::IsNullOrWhiteSpace($reference) -or
        $reference.StartsWith('SYNTHETIC', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Approved-plan reference is empty or synthetic'
    }
    $approvedAt = [string]$wrapper.approvedAtUtc
    $parsedTime = [DateTimeOffset]::MinValue
    if (-not $approvedAt.EndsWith('Z') -or
        -not [DateTimeOffset]::TryParse(
            $approvedAt,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsedTime)) {
        throw 'Approved-plan timestamp must be a valid UTC timestamp ending in Z'
    }
    $allowlist = @($Selection.Document.approvalReferenceAllowlist)
    if ($allowlist.Count -eq 0 -or $allowlist -cnotcontains $reference) {
        throw 'Approval reference is not present in the reviewed selection allowlist'
    }
    return [pscustomobject]@{
        Path = $full
        Sha256 = $sha
        Reference = $reference
        ApprovedAtUtc = $approvedAt
    }
}

function Get-M23SystemPreflight {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)]$Build,
        [Parameter(Mandatory = $true)][string]$ArchiveRoot
    )
    $state = Get-M23RepositoryState $RepositoryRoot
    Assert-M23BuildMatchesRepository $state $Build
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($null -eq $os -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'M23 pilot observations require the qualified 64-bit Windows host'
    }
    if ([long]$os.FreePhysicalMemory * 1024 -lt $script:M23PilotResourceMinimumBytes) {
        throw 'M23 pilot requires at least 512 MiB available physical memory'
    }
    Assert-M23LocalArchiveVolumeForPath $ArchiveRoot
    return $state
}

function Assert-M23LocalArchiveVolume {
    param(
        [object]$DriveType,
        [object]$IsReady,
        [object]$AvailableFreeBytes
    )
    if ($DriveType -isnot [System.IO.DriveType] -or
        $DriveType -ne [System.IO.DriveType]::Fixed) {
        throw 'Archive root must be on a known local fixed volume'
    }
    if ($IsReady -isnot [bool] -or -not $IsReady) {
        throw 'Archive volume readiness is unavailable'
    }
    if ($AvailableFreeBytes -isnot [long] -or
        $AvailableFreeBytes -lt $script:M23PilotResourceMinimumBytes) {
        throw 'Archive volume free-space information is unavailable or below 512 MiB'
    }
}

function Assert-M23LocalArchiveVolumeForPath {
    param([Parameter(Mandatory = $true)][string]$ArchiveRoot)
    $driveRoot = [System.IO.Path]::GetPathRoot($ArchiveRoot)
    if ([string]::IsNullOrWhiteSpace($driveRoot) -or
        $driveRoot.StartsWith('\\') -or $driveRoot -notmatch '^[A-Za-z]:\\$') {
        throw 'Archive root must be on a local drive-letter volume'
    }
    try {
        $driveInfo = New-Object System.IO.DriveInfo($driveRoot)
        $driveType = $driveInfo.DriveType
        $isReady = $driveInfo.IsReady
        $availableFreeBytes = $driveInfo.AvailableFreeSpace
    } catch {
        throw "Unable to determine archive volume type/readiness/free space: $($_.Exception.Message)"
    }
    Assert-M23LocalArchiveVolume $driveType $isReady $availableFreeBytes
}

function New-M23LedgerPayload {
    param(
        [string]$SelectionSha256,
        [string]$CandidatePlanSha256,
        [string]$SourceCommit,
        [object[]]$Entries,
        [long]$Sequence = 0
    )
    $logical = 0
    [long]$activeMs = 0
    foreach ($entry in $Entries) {
        $logical += [int]$entry.logicalRuns
        $activeMs += [long]$entry.chargedActiveMilliseconds
    }
    return [ordered]@{
        format = 'cryptobenchmark-m23-pilot-ledger'
        schemaVersion = 1
        selectionSha256 = $SelectionSha256
        candidatePlanSha256 = $CandidatePlanSha256
        sourceGitCommit = $SourceCommit
        sequence = $Sequence
        logicalRunsReserved = $logical
        cumulativeActiveMilliseconds = $activeMs
        entries = @($Entries)
    }
}

function ConvertTo-M23LedgerBytes {
    param([Parameter(Mandatory = $true)]$Payload)
    $payloadText = ConvertTo-Json -InputObject $Payload -Depth 40 -Compress
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadText)
    $payloadHash = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes)
    ) -replace '-', '').ToLowerInvariant()
    $wrapper = [ordered]@{
        payload = $payloadText
        payloadSha256 = $payloadHash
    }
    return [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $wrapper -Compress))
}

function Write-M23AtomicBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    Initialize-M23JobProcessType
    $directory = [System.IO.Path]::GetDirectoryName($Path)
    $temporary = Join-Path $directory (
        '.' + [System.IO.Path]::GetFileName($Path) + '.' +
        [Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = New-Object System.IO.FileStream(
        $temporary,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    [CryptoBenchmark.M23Pilot.JobProcess]::AtomicReplaceDurable($temporary, $Path)
}

function New-M23GroupDirectoryExclusive {
    param([Parameter(Mandatory = $true)][string]$Path)
    [CryptoBenchmark.M23Pilot.JobProcess]::CreateDirectoryExclusive(
        [System.IO.Path]::GetFullPath($Path))
}

function Read-M23Ledger {
    param(
        [string]$LedgerPath,
        [string]$SelectionSha256,
        [string]$CandidatePlanSha256,
        [string]$SourceCommit,
        [object[]]$ResolvedGroups
    )
    if (-not (Test-Path -LiteralPath $LedgerPath -PathType Leaf)) {
        return (New-M23LedgerPayload $SelectionSha256 $CandidatePlanSha256 $SourceCommit @() 0)
    }
    Assert-M23NoReparsePath $LedgerPath | Out-Null
    $ledgerBytes = [System.IO.File]::ReadAllBytes($LedgerPath)
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $wrapper = $strictUtf8.GetString($ledgerBytes) | ConvertFrom-Json
    $wrapperKeys = @($wrapper.PSObject.Properties | ForEach-Object { $_.Name })
    if ($wrapperKeys.Count -ne 2 -or
        $wrapperKeys -cnotcontains 'payload' -or
        $wrapperKeys -cnotcontains 'payloadSha256' -or
        [string]::IsNullOrWhiteSpace([string]$wrapper.payload) -or
        [string]::IsNullOrWhiteSpace([string]$wrapper.payloadSha256)) {
        throw 'Ledger envelope is corrupt'
    }
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$wrapper.payload)
    $actualHash = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash($payloadBytes)
    ) -replace '-', '').ToLowerInvariant()
    if ($actualHash -cne [string]$wrapper.payloadSha256) {
        throw 'Ledger payload checksum mismatch; manual reconciliation required'
    }
    $payload = ([string]$wrapper.payload) | ConvertFrom-Json
    $canonicalPayload = ConvertTo-Json -InputObject $payload -Depth 40 -Compress
    if ($canonicalPayload -cne [string]$wrapper.payload) {
        throw 'Ledger payload is not canonical or contains duplicate/unknown fields'
    }
    $payloadKeys = @($payload.PSObject.Properties | ForEach-Object { $_.Name })
    $expectedPayloadKeys = @('format','schemaVersion','selectionSha256',
        'candidatePlanSha256','sourceGitCommit','sequence','logicalRunsReserved',
        'cumulativeActiveMilliseconds','entries')
    if ($payloadKeys.Count -ne $expectedPayloadKeys.Count -or
        @($expectedPayloadKeys | Where-Object { $_ -notin $payloadKeys }).Count -ne 0) {
        throw 'Ledger payload contains missing or unknown fields'
    }
    if ($payload.format -cne 'cryptobenchmark-m23-pilot-ledger' -or
        [int]$payload.schemaVersion -ne 1 -or
        $payload.selectionSha256 -cne $SelectionSha256 -or
        $payload.candidatePlanSha256 -cne $CandidatePlanSha256 -or
        $payload.sourceGitCommit -cne $SourceCommit) {
        throw 'Ledger provenance differs from this reviewed selection/build'
    }
    $entries = @($payload.entries)
    if ($entries.Count -gt $ResolvedGroups.Count) { throw 'Ledger contains excess reservations' }
    [long]$verifiedRuns = 0
    [long]$verifiedActiveMilliseconds = 0
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $entryKeys = @($entry.PSObject.Properties | ForEach-Object { $_.Name })
        $requiredEntryKeys = @('ordinal','groupId','logicalRuns',
            'reservedMaximumSeconds','chargedActiveMilliseconds','reservedAtUtc',
            'startedAtUtc','completedAtUtc','outputPath','childExitCode',
            'status','reason')
        $unknownEntryKeys = @($entryKeys | Where-Object {
            $_ -notin ($requiredEntryKeys + @('archiveManifestSha256'))
        })
        if ($unknownEntryKeys.Count -ne 0 -or
            @($requiredEntryKeys | Where-Object { $_ -notin $entryKeys }).Count -ne 0) {
            throw 'Ledger entry has missing or unknown fields'
        }
        if ([int]$entry.ordinal -ne ($i + 1) -or
            [string]$entry.groupId -cne [string]$ResolvedGroups[$i].GroupId -or
            [int]$entry.logicalRuns -ne [int]$ResolvedGroups[$i].LogicalRuns) {
            throw 'Ledger is edited, out of order, or inconsistent with the frozen selection'
        }
        if ([string]$entry.status -in @('reserved','started','interrupted','quarantined')) {
            throw 'Ledger has a reserved, interrupted, or quarantined group; manual reconciliation is required before any advance'
        }
        if ([string]$entry.status -ne 'completed') {
            throw "Ledger has an unknown state: $($entry.status)"
        }
        if ([long]$entry.logicalRuns -lt 1 -or
            [long]$entry.chargedActiveMilliseconds -lt 0 -or
            [long]$entry.chargedActiveMilliseconds -gt
                ([long]$entry.reservedMaximumSeconds * 1000)) {
            throw 'Ledger contains an invalid run or duration accounting value'
        }
        $verifiedRuns += [long]$entry.logicalRuns
        $verifiedActiveMilliseconds += [long]$entry.chargedActiveMilliseconds
    }
    if ($verifiedRuns -gt $script:M23PilotMaximumLogicalRuns -or
        $verifiedActiveMilliseconds -gt ([long]$script:M23PilotMaximumWallSeconds * 1000) -or
        [long]$payload.sequence -lt 0 -or
        ($entries.Count -gt 0 -and
            (([long]$payload.sequence -lt $entries.Count) -or
             ([long]$payload.sequence -gt (3 * $entries.Count)))) -or
        ($entries.Count -eq 0 -and [long]$payload.sequence -ne 0) -or
        [long]$payload.logicalRunsReserved -ne $verifiedRuns -or
        [long]$payload.cumulativeActiveMilliseconds -ne $verifiedActiveMilliseconds) {
        throw 'Ledger cumulative caps or derived counters are inconsistent'
    }
    return $payload
}

function Enter-M23LedgerLock {
    param(
        [string]$LockPath,
        [switch]$ReadOnly
    )
    if ($ReadOnly -and -not (Test-Path -LiteralPath $LockPath -PathType Leaf)) {
        throw 'Read-only ledger inspection requires an existing lock file'
    }
    Assert-M23NoReparsePath $LockPath | Out-Null
    $stream = New-Object System.IO.FileStream(
        $LockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::ReadWrite)
    try {
        $stream.Lock(0, 1)
        if (-not $ReadOnly) {
            $stream.SetLength(1)
            $stream.Flush($true)
        }
        return $stream
    } catch {
        $stream.Dispose()
        throw 'Another M23 pilot session holds the exclusive archive lock'
    }
}

function Get-M23GroupOutputPath {
    param([string]$ArchiveRoot, $Group)
    $component = 'group-{0:D2}-{1}' -f $Group.Ordinal, $Group.GroupId
    return Join-Path $ArchiveRoot $component
}

function Write-M23ArchiveManifest {
    param(
        [string]$OutputPath,
        [string]$Disposition,
        [string]$Reason,
        [object]$Build,
        [object]$Approval,
        [object]$Selection,
        [object]$Group,
        [long]$ElapsedMilliseconds
    )
    $summaryPath = Join-Path $OutputPath 'session-summary.txt'
    $summary = @(
        'CryptoBenchmark M23.2 pilot execution evidence'
        ('Disposition: ' + $Disposition)
        ('Reason: ' + $Reason)
        ('Selection SHA-256: ' + $Selection.Sha256)
        ('Candidate plan SHA-256: ' + $script:M23PilotCandidatePlanSha256)
        ('Approved-plan SHA-256: ' + $Approval.Sha256)
        ('Approval reference: ' + $Approval.Reference)
        ('Group ordinal: ' + $Group.Ordinal)
        ('Group ID: ' + $Group.GroupId)
        ('Logical worker runs reserved: ' + $Group.LogicalRuns)
        ('Launch duration including cleanup (ms): ' + $ElapsedMilliseconds)
    ) -join "`r`n"
    $summary += "`r`n"
    [System.IO.File]::WriteAllText(
        $summaryPath, $summary, (New-Object System.Text.UTF8Encoding($false)))

    $files = New-Object System.Collections.Generic.List[object]
    foreach ($file in Get-ChildItem -LiteralPath $OutputPath -File -Force) {
        if ($file.Name -eq 'archive-manifest.json') { continue }
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point found in evidence archive: $($file.FullName)"
        }
        $files.Add([ordered]@{
            path = $file.Name
            bytes = [long]$file.Length
            sha256 = Get-M23FileSha256 $file.FullName
        })
    }
    $fileRecords = $files.ToArray()
    $hostEnvironmentSha256 = ''
    $harnessManifest = Join-Path $OutputPath 'manifest.json'
    if (Test-Path -LiteralPath $harnessManifest -PathType Leaf) {
        try {
            $harnessData = [System.IO.File]::ReadAllText($harnessManifest) | ConvertFrom-Json
            if ($harnessData.environmentSha256 -match '^[0-9a-f]{64}$') {
                $hostEnvironmentSha256 = [string]$harnessData.environmentSha256
            }
        } catch {
            $hostEnvironmentSha256 = ''
        }
    }
    $manifest = [ordered]@{
        format = 'cryptobenchmark-m23-pilot-archive-manifest'
        schemaVersion = 1
        disposition = $Disposition
        reason = $Reason
        selectionSha256 = $Selection.Sha256
        candidatePlanSha256 = $script:M23PilotCandidatePlanSha256
        approvedPlanSha256 = $Approval.Sha256
        approvalReference = $Approval.Reference
        ordinal = [int]$Group.Ordinal
        groupId = $Group.GroupId
        logicalWorkerRunsReserved = [int]$Group.LogicalRuns
        sourceGitCommit = $Build.BuildInfoCommit
        buildType = $Build.BuildType
        applicationSha256 = $Build.ApplicationSha256
        workerSha256 = $Build.WorkerSha256
        hostEnvironmentSha256 = $hostEnvironmentSha256
        createdAtUtc = [DateTime]::UtcNow.ToString('o')
        files = $fileRecords
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $manifest -Depth 30))
    Write-M23AtomicBytes (Join-Path $OutputPath 'archive-manifest.json') $bytes
    return Get-M23FileSha256 (Join-Path $OutputPath 'archive-manifest.json')
}

function Test-M23ChildEvidence {
    param([string]$OutputPath, [object]$Group, [object]$Approval, [object]$Build)
    $evidencePath = Join-Path $OutputPath 'pilot-evidence.json'
    $resultPath = Join-Path $OutputPath 'batch-result.json'
    $markerPath = Join-Path $OutputPath 'success.marker'
    $manifestPath = Join-Path $OutputPath 'manifest.json'
    foreach ($path in @($evidencePath,$resultPath,$markerPath,$manifestPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Successful child omitted required evidence file: $([System.IO.Path]::GetFileName($path))"
        }
    }
    $evidence = [System.IO.File]::ReadAllText($evidencePath) | ConvertFrom-Json
    $marker = [System.IO.File]::ReadAllText($markerPath) | ConvertFrom-Json
    $manifest = [System.IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    $environment = $evidence.environment
    $evidenceSha256 = Get-M23FileSha256 $evidencePath
    $batchResultSha256 = Get-M23FileSha256 $resultPath
    $manifestSha256 = Get-M23FileSha256 $manifestPath
    if ($evidence.status -cne 'completed' -or
        $evidence.evidenceKind -cne 'realPilotObservation' -or
        $evidence.groupId -cne $Group.GroupId -or
        $evidence.candidatePlanSha256 -cne $script:M23PilotCandidatePlanSha256 -or
        $evidence.applicationSha256 -cne $Build.ApplicationSha256 -or
        $evidence.workerSha256 -cne $Build.WorkerSha256 -or
        $environment.gitCommit -cne $Build.BuildInfoCommit -or
        $environment.buildType -cne 'Release' -or
        [string]$evidence.approvedPlanSha256 -cne $Approval.Sha256 -or
        $evidence.approvalReference -cne $Approval.Reference -or
        $manifest.status -cne 'completed' -or
        [string]$manifest.batchResultSha256 -cne $batchResultSha256 -or
        [string]$manifest.evidenceSha256 -cne $evidenceSha256 -or
        $marker.complete -ne $true -or
        $marker.evidenceSha256 -cne $evidenceSha256 -or
        $marker.manifestSha256 -cne $manifestSha256) {
        throw 'C++ observation evidence/marker failed success-provenance checks'
    }
    return $evidence
}

function Get-M23HardChildResult {
    param(
        [string]$Harness,
        [string]$WorkingDirectory,
        [string]$OutputDirectory,
        [string]$ApprovedPlan,
        [string]$ApprovedPlanSha256,
        [string]$GroupId,
        [int]$MaximumSeconds
    )
    if ($script:M23PilotTestMode -and $null -ne $script:M23PilotTestLauncher) {
        return & $script:M23PilotTestLauncher $MaximumSeconds $OutputDirectory
    }
    Initialize-M23JobProcessType
    if ($script:M23PilotChildLaunchCount -ne 0) {
        throw 'This invocation already launched a child; automatic loops are forbidden'
    }
    $script:M23PilotChildLaunchCount++
    $arguments = '--observe-pilot-batch --approved-plan {0} --approved-plan-sha256 {1} --batch-id {2} --output-dir {3} --i-confirm-m23-2-go' -f
        (Quote-M23WindowsArgument $ApprovedPlan),
        (Quote-M23WindowsArgument $ApprovedPlanSha256),
        (Quote-M23WindowsArgument $GroupId),
        (Quote-M23WindowsArgument $OutputDirectory)
    $logPath = Join-Path $OutputDirectory 'child-console.log'
    $graceMilliseconds = [Math]::Min(5000, [Math]::Max(25, ($MaximumSeconds * 1000) / 20))
    return [CryptoBenchmark.M23Pilot.JobProcess]::Run(
        $Harness, $arguments, $WorkingDirectory, $logPath,
        ($MaximumSeconds * 1000), [int]$graceMilliseconds)
}

function Quote-M23WindowsArgument {
    param([string]$Value)
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-M23PilotReservedGroup {
    param(
        [int]$Ordinal,
        [string]$ArchiveRoot,
        [object]$Selection,
        [object[]]$ResolvedGroups,
        [object]$State,
        [object]$Build,
        [object]$Approval,
        [object]$Group,
        [string]$OutputPath
    )
    $ledgerPath = Join-Path $ArchiveRoot 'm23-pilot-ledger.json'
    $lockPath = Join-Path $ArchiveRoot 'm23-pilot-ledger.lock'
    $ledgerLock = Enter-M23LedgerLock $lockPath
    try {
        Assert-M23NoReparsePath $OutputPath | Out-Null
        if (Test-Path -LiteralPath $OutputPath) {
            throw 'Selected group output path appeared after preflight; refusing reuse'
        }
        $null = Assert-M23ArchiveRootBinding $ArchiveRoot $Selection.Sha256 -Create
        $ledger = Read-M23Ledger $ledgerPath $Selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 $State.Head $ResolvedGroups
        Assert-M23LedgerMatchesAnchor $ledgerPath $ArchiveRoot `
            $Selection.Sha256 $ledger
        $entries = @($ledger.entries)
        if ($Ordinal -ne ($entries.Count + 1)) {
            throw "Only the next unattempted ordinal is permitted; expected $($entries.Count + 1)"
        }
        if ($Ordinal -lt 1 -or $Ordinal -gt $ResolvedGroups.Count -or
            $Group.GroupId -cne $ResolvedGroups[$Ordinal - 1].GroupId) {
            throw 'Prepared group does not match the fixed selection ordinal'
        }
        $maximumSeconds = Get-M23RemainingReservation $ledger $Group.LogicalRuns
        $entry = [ordered]@{
            ordinal = $Ordinal
            groupId = $Group.GroupId
            logicalRuns = $Group.LogicalRuns
            reservedMaximumSeconds = $maximumSeconds
            chargedActiveMilliseconds = [long]0
            reservedAtUtc = [DateTime]::UtcNow.ToString('o')
            startedAtUtc = $null
            completedAtUtc = $null
            outputPath = $OutputPath
            childExitCode = $null
            status = 'reserved'
            reason = ''
        }
        $entries += $entry
        $newLedger = New-M23LedgerPayload $Selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 $State.Head $entries `
            ([long]$ledger.sequence + 1)
        Write-M23LedgerState $ledgerPath $ArchiveRoot $Selection.Sha256 $newLedger
        $ledger = $newLedger

        try {
            New-M23GroupDirectoryExclusive $OutputPath
            Assert-M23NoReparsePath $OutputPath | Out-Null
            $entry.startedAtUtc = [DateTime]::UtcNow.ToString('o')
            $entry.status = 'started'
            $newLedger = New-M23LedgerPayload $Selection.Sha256 `
                $script:M23PilotCandidatePlanSha256 $State.Head $entries `
                ([long]$ledger.sequence + 1)
            Write-M23LedgerState $ledgerPath $ArchiveRoot $Selection.Sha256 $newLedger
            $ledger = $newLedger

            $child = Get-M23HardChildResult $Build.Harness $Build.BuildRoot `
                $OutputPath $Approval.Path $Approval.Sha256 $Group.GroupId $maximumSeconds
            $elapsedMs = [long]$child.ElapsedMilliseconds
            $entry.chargedActiveMilliseconds = $elapsedMs
            $entry.childExitCode = [int]$child.ExitCode
            $entry.completedAtUtc = [DateTime]::UtcNow.ToString('o')

            $disposition = 'QUARANTINED'
            $reason = ''
            if ($child.TimedOut) {
                $entry.status = 'interrupted'
                $reason = 'Hard child timeout; no retry or next group permitted.'
            } elseif (-not $child.TreeTerminated) {
                $entry.status = 'interrupted'
                $reason = 'Process-tree termination could not be verified; manual reconciliation required.'
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$child.Error)) {
                $entry.status = 'quarantined'
                $reason = 'Supervisor reported a process-tree execution error: ' + $child.Error
            } elseif ([int]$child.ExitCode -ne 0) {
                $entry.status = 'quarantined'
                $reason = 'Child returned nonzero; evidence is retained but not accepted.'
            } else {
                try {
                    $null = Test-M23ChildEvidence $OutputPath $Group $Approval $Build
                    $entry.status = 'completed'
                    $disposition = 'COMPLETED'
                    $reason = 'C++ harness reported validated completed pilot evidence.'
                } catch {
                    $entry.status = 'quarantined'
                    $reason = $_.Exception.Message
                }
            }
            $entry.reason = $reason
            $archiveManifestSha = Write-M23ArchiveManifest $OutputPath $disposition `
                $reason $Build $Approval $Selection $Group $elapsedMs
            $entry.archiveManifestSha256 = $archiveManifestSha
            $newLedger = New-M23LedgerPayload $Selection.Sha256 `
                $script:M23PilotCandidatePlanSha256 $State.Head $entries `
                ([long]$ledger.sequence + 1)
            Write-M23LedgerState $ledgerPath $ArchiveRoot $Selection.Sha256 $newLedger
            $ledger = $newLedger
            if ($entry.status -eq 'interrupted') {
                throw 'Child termination is uncertain; ledger is fail-closed and manual reconciliation is required'
            }
            if ($entry.status -eq 'quarantined') {
                throw "Child evidence quarantined: $reason"
            }
            Write-Output "RESULT: GROUP $Ordinal COMPLETED; NO AUTOMATIC ADVANCE"
            Write-Output "GROUP_ID=$($Group.GroupId)"
            Write-Output "LOGICAL_RUNS=$($Group.LogicalRuns)"
            Write-Output "OUTPUT=$OutputPath"
            Write-Output "ARCHIVE_MANIFEST_SHA256=$archiveManifestSha"
        } catch {
            if ($entry.status -in @('reserved','started')) {
                $entry.status = 'interrupted'
                $entry.reason = $_.Exception.Message
                $entry.chargedActiveMilliseconds = [long]$entry.reservedMaximumSeconds * 1000
                try {
                    if (Test-Path -LiteralPath $OutputPath -PathType Container) {
                        $null = Write-M23ArchiveManifest $OutputPath 'QUARANTINED' `
                            $entry.reason $Build $Approval $Selection $Group `
                            $entry.chargedActiveMilliseconds
                    }
                } catch {
                    $entry.reason += '; archive manifest failed: ' + $_.Exception.Message
                }
                $newLedger = New-M23LedgerPayload $Selection.Sha256 `
                    $script:M23PilotCandidatePlanSha256 $State.Head $entries `
                    ([long]$ledger.sequence + 1)
                Write-M23LedgerState $ledgerPath $ArchiveRoot $Selection.Sha256 $newLedger
                $ledger = $newLedger
            }
            throw
        }
    } finally {
        $ledgerLock.Unlock(0, 1)
        $ledgerLock.Dispose()
    }
}

function Invoke-M23PilotExecute {
    param(
        [int]$Ordinal,
        [string]$ArchiveRoot,
        [string]$ApprovedPlan,
        [string]$ApprovedPlanSha256,
        [string]$SelectionSha256,
        [string]$ApprovalReference,
        [bool]$IConfirmM232Go
    )
    if (-not $IConfirmM232Go) { throw 'Explicit -IConfirmM232Go is required' }
    $repo = Get-M23RepoRoot
    $selection = Get-M23Selection
    if ($selection.Sha256 -cne $SelectionSha256.ToLowerInvariant()) {
        throw 'Exact selection-file SHA-256 mismatch'
    }
    $report = Invoke-M23HarnessDryRun `
        (Join-Path $repo 'build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe') `
        $script:M23PilotCandidatePlanSha256
    $resolved = Resolve-M23Selection $selection $report.candidatePlan
    if ($Ordinal -lt 1 -or $Ordinal -gt $resolved.Count) {
        throw 'Ordinal is outside the fixed 23-group selection'
    }
    $state = Get-M23RepositoryState $repo
    $build = Get-M23BuildProvenance $repo
    if ($null -ne $script:M23PilotTestEnvironment) {
        $state = & $script:M23PilotTestEnvironment.RepositoryState $repo
        $build = & $script:M23PilotTestEnvironment.BuildProvenance $repo
    }
    $archive = Assert-M23ExternalArchiveRoot $ArchiveRoot $repo
    $state = Get-M23SystemPreflight $repo $build $archive
    $approval = Read-M23ApprovedPlan $ApprovedPlan $ApprovedPlanSha256 `
        $selection $report.candidatePlan
    if ($approval.Reference -cne $ApprovalReference) {
        throw 'CLI approval reference differs from the approved-plan reference'
    }
    $group = $resolved[$Ordinal - 1]
    $output = Get-M23GroupOutputPath $archive $group
    Assert-M23NoReparsePath $output | Out-Null
    if (Test-Path -LiteralPath $output) {
        throw 'Selected group output path already exists; evidence is never overwritten'
    }
    if ($null -ne $script:M23PilotTestEnvironment) {
        $script:M23PilotTestEnvironment.BeforeReservation.Invoke(
            $selection, $report, $resolved, $state, $build, $archive, $approval, $group)
    }

    Invoke-M23PilotReservedGroup $Ordinal $archive $selection $resolved `
        $state $build $approval $group $output
}

function Invoke-M23PilotInspect {
    param([string]$ArchiveRoot)
    $repo = Get-M23RepoRoot
    $selection = Get-M23Selection
    $report = Invoke-M23HarnessDryRun `
        (Join-Path $repo 'build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe') `
        $script:M23PilotCandidatePlanSha256
    $resolved = Resolve-M23Selection $selection $report.candidatePlan
    $archive = Assert-M23ExternalArchiveRoot $ArchiveRoot $repo
    $ledgerPath = Join-Path $archive 'm23-pilot-ledger.json'
    if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
        Write-Output 'LEDGER=NOT_CREATED; no reservation or observation recorded'
        return
    }
    $lockPath = Join-Path $archive 'm23-pilot-ledger.lock'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'Ledger exists without its lock file; manual reconciliation required'
    }
    $lock = Enter-M23LedgerLock $lockPath -ReadOnly
    try {
        $null = Assert-M23ArchiveRootBinding $archive $selection.Sha256
        $state = Get-M23RepositoryState $repo
        $ledger = Read-M23Ledger $ledgerPath $selection.Sha256 `
            $script:M23PilotCandidatePlanSha256 $state.Head $resolved
        Assert-M23LedgerMatchesAnchor $ledgerPath $archive `
            $selection.Sha256 $ledger
        Write-Output 'LEDGER=VALID; inspection did not modify files'
        Write-Output "GROUPS=$($ledger.entries.Count)"
        Write-Output "LOGICAL_RUNS_RESERVED=$($ledger.logicalRunsReserved)"
        Write-Output "CUMULATIVE_ACTIVE_MS=$($ledger.cumulativeActiveMilliseconds)"
        foreach ($entry in $ledger.entries) {
            Write-Output ('ORDINAL={0} STATUS={1} GROUP={2} RUNS={3} MS={4}' -f
                $entry.ordinal, $entry.status, $entry.groupId,
                $entry.logicalRuns, $entry.chargedActiveMilliseconds)
        }
    } finally {
        $lock.Unlock(0, 1)
        $lock.Dispose()
    }
}

function Parse-M23SessionArguments {
    param([string[]]$Arguments)
    $values = @{}
    $switches = @{}
    $allowedSwitches = @('-DryRun','-InspectLedger','-ExecuteNext','-IConfirmM232Go')
    $allowedValues = @('-Ordinal','-ArchiveRoot','-ApprovedPlan',
        '-ApprovedPlanSha256','-SelectionSha256','-ApprovalReference')
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $name = [string]$Arguments[$i]
        if ($name -notmatch '^-[A-Za-z][A-Za-z0-9]*$') {
            throw "Unexpected positional/unknown argument: $name"
        }
        $normalized = $name.ToLowerInvariant()
        if ($values.ContainsKey($normalized) -or $switches.ContainsKey($normalized)) {
            throw "Duplicate option: $name"
        }
        if ($allowedSwitches -icontains $name) {
            $switches[$normalized] = $true
        } elseif ($allowedValues -icontains $name) {
            if (($i + 1) -ge $Arguments.Count -or
                ([string]$Arguments[$i + 1]).StartsWith('-')) {
                throw "$name requires one value"
            }
            $i++
            $values[$normalized] = [string]$Arguments[$i]
        } else {
            throw "Unknown option: $name"
        }
    }
    $modes = @(@('-dryrun','-inspectledger','-executenext') |
        Where-Object { $switches.ContainsKey($_) })
    if ($modes.Count -gt 1) { throw 'Execution modes are mutually exclusive' }
    $mode = if ($modes.Count -eq 0) { 'DryRun' } else {
        switch ($modes[0]) {
            '-dryrun' { 'DryRun' }
            '-inspectledger' { 'InspectLedger' }
            '-executenext' { 'ExecuteNext' }
        }
    }
    if ($mode -eq 'DryRun' -and
        ($values.Count -gt 0 -or $switches.ContainsKey('-iconfirmm232go'))) {
        throw 'DryRun accepts no archive, approval, ordinal, or GO options'
    }
    if ($mode -eq 'InspectLedger' -and
        ($values.Count -ne 1 -or -not $values.ContainsKey('-archiveroot') -or
         $switches.ContainsKey('-iconfirmm232go'))) {
        throw 'InspectLedger requires only -ArchiveRoot'
    }
    if ($mode -eq 'ExecuteNext') {
        $required = @('-ordinal','-archiveroot','-approvedplan',
            '-approvedplansha256','-selectionsha256','-approvalreference')
        if (-not $switches.ContainsKey('-iconfirmm232go') -or
            $values.Count -ne $required.Count -or
            @($required | Where-Object { -not $values.ContainsKey($_) }).Count -ne 0) {
            throw 'ExecuteNext requires all named approval/archive/hash options and -IConfirmM232Go'
        }
        $ordinal = 0
        if (-not [int]::TryParse($values['-ordinal'], [ref]$ordinal) -or
            $ordinal -lt 1 -or $ordinal -gt 23) {
            throw '-Ordinal must be an integer from 1 through 23'
        }
        $values['-ordinal'] = $ordinal
    }
    return [pscustomobject]@{ Mode = $mode; Values = $values; Switches = $switches }
}

function Invoke-M23PilotSession {
    param([string[]]$Arguments = @())
    $parsed = Parse-M23SessionArguments $Arguments
    switch ($parsed.Mode) {
        'DryRun' {
            $repo = Get-M23RepoRoot
            $selection = Get-M23Selection
            $build = Get-M23BuildProvenance $repo
            $report = Invoke-M23HarnessDryRun $build.Harness $script:M23PilotCandidatePlanSha256
            $resolved = Resolve-M23Selection $selection $report.candidatePlan
            Write-Output 'M23.2-PREP PROPOSED SELECTION - NO OBSERVATIONS'
            Write-Output "candidatePlanSha256=$script:M23PilotCandidatePlanSha256"
            Write-Output "selectionSha256=$($selection.Sha256)"
            Write-Output "groups=$($resolved.Count); logicalWorkerRuns=27; canonicalCaseTypes=12"
            Write-Output "selectionStatus=PROPOSED_NOT_APPROVED; measurementAuthorized=false"
            foreach ($group in $resolved) {
                Write-Output ('{0:D2} {1} logicalRuns={2}' -f
                    $group.Ordinal, $group.GroupId, $group.LogicalRuns)
            }
            Write-Output 'RESULT: PASS - NO OBSERVATIONS'
        }
        'InspectLedger' {
            Invoke-M23PilotInspect $parsed.Values['-archiveroot']
        }
        'ExecuteNext' {
            Invoke-M23PilotExecute `
                $parsed.Values['-ordinal'] `
                $parsed.Values['-archiveroot'] `
                $parsed.Values['-approvedplan'] `
                $parsed.Values['-approvedplansha256'] `
                $parsed.Values['-selectionsha256'] `
                $parsed.Values['-approvalreference'] `
                $parsed.Switches.ContainsKey('-iconfirmm232go')
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-M23PilotSession -Arguments @($args)
    } catch {
        [Console]::Error.WriteLine('FAIL: ' + $_.Exception.Message)
        throw
    }
}
