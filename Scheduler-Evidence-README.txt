Windows Server 2022 vs 2025 VMware CPU context-switch investigation

FILES
1. Collect-WindowsSchedulerEvidence.ps1  (run on EACH virtual machine)
2. Compare-WindowsSchedulerEvidence.ps1  (run after collecting two folders)

RUN (Windows PowerShell 5.1, elevated, during equivalent sustained benchmark load)
  Set-ExecutionPolicy -Scope Process Bypass
  .\Collect-WindowsSchedulerEvidence.ps1 -Label WS2022-Benchmark -Samples 30 -IntervalSeconds 2
  .\Collect-WindowsSchedulerEvidence.ps1 -Label WS2025-Benchmark -Samples 30 -IntervalSeconds 2

OPTIONAL CAUSAL TRACE (run separate pass on both VMs, preferably not in initial low-impact baseline)
  .\Collect-WindowsSchedulerEvidence.ps1 -Label WS2025-ETW -Samples 30 -IntervalSeconds 2 -TraceETW

Each run produces C:\SchedulerEvidence\HOST_LABEL_TIMESTAMP\ and a summary ZIP.
The ETL (if requested) is in the folder but deliberately excluded from its ZIP.

On an analysis workstation, extract two ZIPs and compare:
  .\Compare-WindowsSchedulerEvidence.ps1 -Server2022 'C:\runs\2022' -Server2025 'C:\runs\2025'

KEY OUTPUTS
  Process_ByPID_Averages.csv: every process PID sampled (including zero-rate)
  Process_ByName_Averages.csv: all process names aggregated across PIDs
  Process_Samples_All.csv: every process, every sample
  Thread_Samples_All.csv: every visible thread, every sample
  System_Samples.csv: system total, sum of thread rates and reconciliation gap
  Processor_Samples_PerCPU.csv: system/per-CPU CPU, DPC, interrupt counters
  Configuration / driver JSON and TXT files
  Scheduler_Trace.etl: optional WPR trace for Windows Performance Analyzer

NOTES
- Formatted WMI thread counters return estimates of recent context switches/second,
  not event-by-event switches; separate sampling calls are not perfectly synchronized.
- Thread switch count is assigned to the switched thread, not necessarily the
  thread that caused the switch; ETW is necessary for readying stacks and causes.
- Idle/system pseudo-processes appear where exposed by the performance provider.
- Very short lived threads may be absent, and PIDs may be reused.
- WMI polling all threads adds overhead on high-thread-count systems.
- Run each configuration multiple times and at matched workload/throughput.
- WPR GeneralProfile records context switches, ready-thread, interrupt and DPC events.
- ETL file/exports may reveal process names and sensitive operational metadata.
