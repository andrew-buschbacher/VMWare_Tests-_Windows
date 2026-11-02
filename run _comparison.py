#!/usr/bin/env python3
"""Orchestrate sequential Windows SSH + vCenter CPU evidence collection from macOS.

No Windows guest-side agent is installed. Requires preconfigured OpenSSH Server,
permission to execute an elevated PowerShell collector, pyVmomi and Paramiko.
"""
from __future__ import annotations

import argparse
import base64
import csv
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import zipfile

try:
    import paramiko
except ImportError:
    sys.exit("Missing Paramiko. Run: python3 -m pip install paramiko pyvmomi")

ROOT = Path(__file__).resolve().parent
COLLECTOR = ROOT / 'Collect-WindowsSchedulerEvidence.ps1'
VC_SCRIPT = ROOT / 'collect_vcenter_cpu.py'


def utc_now():
    return datetime.now(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def parse_stamp(value):
    result = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timestamp is not timezone aware: ' + value)
    return result.astimezone(timezone.utc)


def json_out(path, payload):
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def parse_target(arg):
    """Accept LABEL|SSH_USER@WINDOWS_HOST|EXACT_VCENTER_VM_NAME."""
    parts = arg.split('|', 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError('Target must be LABEL|SSH_USER@HOST|EXACT_VCENTER_VM_NAME')
    label, ssh, vm = (x.strip() for x in parts)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,30}', label):
        raise argparse.ArgumentTypeError('Target label must be 1-30 letters, digits, underscore or hyphen')
    if '@' not in ssh:
        raise argparse.ArgumentTypeError('Target needs SSH_USER@WINDOWS_HOST')
    user, host = ssh.rsplit('@', 1)
    if not user or not host or not vm:
        raise argparse.ArgumentTypeError('Target user, host, and vCenter VM name must not be empty')
    return {'label': label, 'ssh_user': user, 'ssh_host': host, 'vm_name': vm}


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--target', action='append', type=parse_target, required=True,
                   help="Repeat twice, in desired order: '2022|admin@server2022|VM NAME IN VCENTER'")
    p.add_argument('--vcenter', required=True, help='vCenter FQDN')
    p.add_argument('--vcenter-user', required=True, help='Read-only vCenter username')
    p.add_argument('--vcenter-password-env', help='Name of local environment variable holding vCenter password')
    p.add_argument('--vcenter-ca-file', help='PEM CA certificate for vCenter TLS validation')
    p.add_argument('--insecure-vcenter', action='store_true', help='Lab only: disable vCenter certificate validation')
    p.add_argument('--ssh-port', type=int, default=22)
    p.add_argument('--ssh-key', help='Private key to use for Windows SSH (otherwise SSH agent/default keys)')
    p.add_argument('--ssh-password', action='store_true', help='Prompt for Windows SSH password separately for each VM')
    p.add_argument('--ssh-known-hosts', default='~/.ssh/known_hosts', help='Verified host keys file')
    p.add_argument('--samples', type=int, default=30)
    p.add_argument('--interval-seconds', type=int, default=2)
    p.add_argument('--trace-etw', action='store_true', help='Record a Windows WPR GeneralProfile ETL')
    p.add_argument('--download-etl', action='store_true', help='Transfer the potentially large ETL to the Mac')
    p.add_argument('--output', default=None, help='Local output directory')
    p.add_argument('--timeout-seconds', type=int, default=3600,
                   help='Per Windows collection timeout; default 3600')
    p.add_argument('--skip-vcenter-preflight', action='store_true',
                   help='Skip vCenter identity preflight (not recommended)')
    a = p.parse_args()
    if len(a.target) != 2:
        p.error('Exactly two --target arguments required for this comparison')
    if a.target[0]['label'] == a.target[1]['label']:
        p.error('Use different labels for the two targets')
    if not 2 <= a.samples <= 10000:
        p.error('--samples must be from 2 to 10000')
    if not 1 <= a.interval_seconds <= 300:
        p.error('--interval-seconds must be from 1 to 300')
    if a.timeout_seconds < 60:
        p.error('--timeout-seconds must be at least 60')
    if a.download_etl and not a.trace_etw:
        p.error('--download-etl requires --trace-etw')
    if a.insecure_vcenter and a.vcenter_ca_file:
        p.error('Use either a CA file or --insecure-vcenter, not both')
    if not COLLECTOR.is_file() or not VC_SCRIPT.is_file():
        p.error('The Windows collector and vCenter script must be beside this program')
    return a


def powershell_literal(value):
    return "'" + value.replace("'", "''") + "'"


def encode_powershell(program):
    return base64.b64encode(program.encode('utf-16le')).decode('ascii')


def remote_powershell_command(program):
    return 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + encode_powershell(program)


def remote_call(ssh, script, timeout=60, log=None):
    cmd = remote_powershell_command(script)
    channel = ssh.get_transport().open_session(timeout=15)
    channel.settimeout(1.0)
    channel.exec_command(cmd)
    stdout = bytearray()
    stderr = bytearray()
    start = time.monotonic()
    try:
        while True:
            while channel.recv_ready():
                chunk = channel.recv(32768)
                stdout.extend(chunk)
                if log:
                    log.write(chunk.decode('utf-8', errors='replace'))
                    log.flush()
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(32768)
                stderr.extend(chunk)
                if log:
                    log.write(chunk.decode('utf-8', errors='replace'))
                    log.flush()
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                status = channel.recv_exit_status()
                break
            if time.monotonic() - start > timeout:
                raise TimeoutError(f'Remote PowerShell exceeded {timeout}s; recording might need cleanup on VM')
            time.sleep(0.1)
    finally:
        channel.close()
    text_stdout = stdout.decode('utf-8-sig', errors='replace')
    text_stderr = stderr.decode('utf-8-sig', errors='replace')
    if status != 0:
        raise RuntimeError(f'Remote PowerShell exit {status}: {text_stderr[-1200:]}\n{text_stdout[-1200:]}')
    return text_stdout


def ssh_connect(target, args, password):
    ssh = paramiko.SSHClient()
    keys = Path(args.ssh_known_hosts).expanduser()
    if not keys.exists():
        raise FileNotFoundError(f'No known_hosts file at {keys}. Connect using macOS ssh first and verify the Windows SSH host key.')
    ssh.load_host_keys(str(keys))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    kwargs = dict(hostname=target['ssh_host'], port=args.ssh_port,
                  username=target['ssh_user'], timeout=20, banner_timeout=20, auth_timeout=30)
    if args.ssh_key:
        kwargs['key_filename'] = str(Path(args.ssh_key).expanduser())
        kwargs['allow_agent'] = False
        kwargs['look_for_keys'] = False
    else:
        kwargs['allow_agent'] = True
        kwargs['look_for_keys'] = not args.ssh_password
    if password is not None:
        kwargs['password'] = password
        kwargs['look_for_keys'] = False
        kwargs['allow_agent'] = False
    ssh.connect(**kwargs)
    return ssh


def preflight_vcenter(args, password, output):
    if args.skip_vcenter_preflight:
        return
    env = os.environ.copy()
    env['__SCHED_VC_PASS'] = password
    cmd = [sys.executable, str(VC_SCRIPT), '--vcenter', args.vcenter,
           '--user', args.vcenter_user, '--password-env', '__SCHED_VC_PASS',
           '--interval', '20', '--list-vms', '--output', str(output / 'vcenter-preflight')]
    for t in args.target:
        cmd += ['--vm', t['vm_name']]
    if args.vcenter_ca_file:
        cmd += ['--ca-file', args.vcenter_ca_file]
    if args.insecure_vcenter:
        cmd += ['--insecure']
    print('\nChecking vCenter connection and exact VM identities...')
    check = subprocess.run(cmd, env=env, capture_output=True, text=True)
    (output / 'vcenter-preflight.log').write_text(check.stdout + check.stderr, encoding='utf-8')
    if check.returncode:
        raise RuntimeError(f'vCenter preflight failed:\n{check.stderr[-1200:]}')
    print(check.stdout.rstrip())


def sftp_path(windows_path):
    # Windows OpenSSH's SFTP subsystem accepts drive-qualified forward-slash paths.
    return '/' + windows_path.replace('\\', '/').lstrip('/')


def find_zip(sftp, remote_output_dir):
    directory = sftp_path(remote_output_dir)
    found = [ent.filename for ent in sftp.listdir_attr(directory) if ent.filename.lower().endswith('.zip')]
    if len(found) != 1:
        raise RuntimeError(f'Expected one Windows summary ZIP in {remote_output_dir}; found {found}')
    return directory.rstrip('/') + '/' + found[0]


def extract_zip_safely(zip_path, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        if not names:
            raise RuntimeError(f'Empty Windows ZIP: {zip_path}')
        for info in archive.infolist():
            name = info.filename.replace('\\', '/')
            if name.startswith('/') or '..' in Path(name).parts or ':' in name:
                raise RuntimeError('Invalid ZIP member path: ' + info.filename)
        archive.extractall(destination)


def read_windows_window(extracted):
    path = extracted / 'System_Samples.csv'
    if not path.is_file():
        raise FileNotFoundError('Missing System_Samples.csv in Windows ZIP')
    with path.open(encoding='utf-8-sig', newline='') as fp:
        rows = list(csv.DictReader(fp))
    times = sorted(parse_stamp(row['TimestampUTC']) for row in rows)
    if len(times) < 2:
        raise RuntimeError('Need at least two valid Windows system sample timestamps')
    # The same timestamp is captured once per sample; add 30s on both ends
    # to include corresponding vCenter 20-second buckets. Retain exact times.
    return times[0], times[-1], len(rows)


def windows_run(target, args, root):
    label = target['label']
    local = root / 'runs' / label
    local.mkdir(parents=True, exist_ok=True)
    pw = getpass.getpass(f'Windows SSH password for {target["ssh_user"]}@{target["ssh_host"]}: ') if args.ssh_password else None
    print(f'\n[{label}] Connecting to Windows {target["ssh_host"]} over SSH...')
    ssh = ssh_connect(target, args, pw)
    try:
        stage = 'C:\\SchedulerEvidence\\MacControl_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + label
        remote_script = stage + '\\Collect-WindowsSchedulerEvidence.ps1'
        remote_output = stage + '\\output'
        prep = '$ErrorActionPreference="Stop"; New-Item -ItemType Directory -Path ' + powershell_literal(stage) + ' -Force | Out-Null; ' + \
               '$user=[Security.Principal.WindowsIdentity]::GetCurrent();' + \
               '$admin=([Security.Principal.WindowsPrincipal]$user).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);' + \
               'if(-not $admin){throw "SSH session is not elevated. Use an authorized admin SSH login."};' + \
               'Write-Output ("HOSTUTC="+[DateTime]::UtcNow.ToString("o"));' + \
               'Write-Output ("IDENTITY="+$user.Name)'
        print('  Checking elevated Windows permissions and staging collector...')
        local_time_before = utc_now()
        preflight = remote_call(ssh, prep, timeout=60)
        local_time_after = utc_now()
        (local / 'ssh-preflight.log').write_text(preflight, encoding='utf-8')
        guest_utc = next((line.split('HOSTUTC=', 1)[1].strip() for line in preflight.splitlines() if 'HOSTUTC=' in line), None)
        clock_skew_seconds = None
        if guest_utc:
            guest_clock = parse_stamp(guest_utc)
            local_midpoint = local_time_before + (local_time_after - local_time_before) / 2
            clock_skew_seconds = round((guest_clock - local_midpoint).total_seconds(), 3)
            print(f'  Approximate Windows-to-Mac UTC clock skew: {clock_skew_seconds:+.3f}s')
            if abs(clock_skew_seconds) >= 5:
                print('  WARNING: Windows clock skew >=5s may prevent exact Windows/vCenter timeline alignment.')
        with ssh.open_sftp() as sftp:
            sftp.put(str(COLLECTOR), sftp_path(remote_script))
        print(f'  Starting {args.samples} samples; target interval {args.interval_seconds}s...')
        remote_code = (
            '$ErrorActionPreference="Stop";'
            'try {'
            '& ' + powershell_literal(remote_script) +
            ' -Label ' + powershell_literal('Scheduler-' + label) +
            ' -Samples ' + str(args.samples) +
            ' -IntervalSeconds ' + str(args.interval_seconds) +
            ' -OutputRoot ' + powershell_literal(remote_output) +
            (' -TraceETW' if args.trace_etw else '') + ';'
            'if (-not $?) {throw "Windows collector failed"};'
            '} catch { Write-Error $_; exit 1 };'
            'exit 0'
        )
        with (local / 'windows-collector.log').open('w', encoding='utf-8') as logfile:
            remote_call(ssh, remote_code, timeout=args.timeout_seconds, log=logfile)
        with ssh.open_sftp() as sftp:
            remote_zip = find_zip(sftp, remote_output)
            dest_zip = local / 'windows_summary.zip'
            sftp.get(remote_zip, str(dest_zip))
            print(f'  Downloaded {dest_zip.name} ({dest_zip.stat().st_size:,} bytes).')
            with zipfile.ZipFile(dest_zip) as zf:
                if zf.testzip() is not None:
                    raise RuntimeError('Windows ZIP failed checksum verification')
            extracted = local / 'windows'
            extract_zip_safely(dest_zip, extracted)
            if args.download_etl:
                data_dirs = [name for name in sftp.listdir(sftp_path(remote_output)) if name.lower().endswith('.zip') is False]
                if len(data_dirs) != 1:
                    raise RuntimeError(f'Cannot identify Windows ETL folder in {remote_output}: {data_dirs}')
                remote_etl = sftp_path(remote_output) + '/' + data_dirs[0] + '/Scheduler_Trace.etl'
                sftp.get(remote_etl, str(local / 'Scheduler_Trace.etl'))
                print('  Downloaded ETL (may be large).')
        first, last, n = read_windows_window(extracted)
        # Note that vCenter's 20s buckets may be partially outside the Windows
        # run. Keep per-timestamp data and inspect overlap in post-analysis.
        metadata = {
            'label': label,
            'ssh_host': target['ssh_host'], 'ssh_user': target['ssh_user'],
            'vcenter_vm_name': target['vm_name'],
            'remote_work_dir': stage, 'remote_script': remote_script,
            'first_windows_sample_utc': iso(first),
            'last_windows_sample_utc': iso(last),
            'number_of_windows_samples': n,
            'windows_zip_sha256': hashlib.sha256(dest_zip.read_bytes()).hexdigest(),
            'windows_zip_bytes': dest_zip.stat().st_size,
            'approx_guest_minus_mac_clock_seconds': clock_skew_seconds,
        }
        json_out(local / 'run_manifest.json', metadata)
        print(f'  Windows sample window: {iso(first)} to {iso(last)}')
        return first, last, metadata
    finally:
        ssh.close()


def vcenter_run(target, args, root, passphrase, first, last):
    label = target['label']
    local = root / 'runs' / label
    window_start = first - timedelta(seconds=30)
    window_end = last + timedelta(seconds=30)
    # Keep vCenter QueryPerf <= typical 1-hour real-time retention window.
    env = os.environ.copy()
    env['__SCHED_VC_PASS'] = passphrase
    cmd = [sys.executable, str(VC_SCRIPT), '--vcenter', args.vcenter,
           '--user', args.vcenter_user, '--password-env', '__SCHED_VC_PASS',
           '--vm', target['vm_name'], '--interval', '20',
           '--start', iso(window_start), '--end', iso(window_end),
           '--output', str(local / 'vcenter')]
    if args.vcenter_ca_file:
        cmd.extend(['--ca-file', args.vcenter_ca_file])
    if args.insecure_vcenter:
        cmd += ['--insecure']
    print(f'  Querying vCenter for {target["vm_name"]}: {iso(window_start)} — {iso(window_end)}')
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    (local / 'vcenter-collector.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    if result.returncode != 0:
        raise RuntimeError(f'vCenter collection failed for {label}: {result.stderr[-1500:]}')
    print(result.stdout.rstrip())
    meta_path = local / 'vcenter' / 'collection_metadata.json'
    meta = json.loads(meta_path.read_text(encoding='utf-8')) if meta_path.exists() else {}
    inventory = local / 'vcenter' / 'inventory.json'
    inventory_obj = json.loads(inventory.read_text(encoding='utf-8')) if inventory.exists() else None
    print('  vCenter timing data collected.')
    return {'query_start_utc': iso(window_start), 'query_end_utc': iso(window_end),
            'vcenter_metadata': meta, 'vm_inventory': inventory_obj}


def read_csv(path):
    with path.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def asfloat(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def as_optional_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def write_csv(path, rows, fields):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_thread_summary(local):
    """Summarize every observed (PID, TID) without dropping low-switch threads."""
    inventory = read_csv(local / 'windows' / 'Process_ByPID_Averages.csv')
    pid_to_name = {r['PID']: r['ProcessName'] for r in inventory}
    samples = read_csv(local / 'windows' / 'Thread_Samples_All.csv')
    system_rows = read_csv(local / 'windows' / 'System_Samples.csv')
    count_all = len(system_rows)
    groups = {}
    for row in samples:
        key = (row['PID'], row['TID'])
        if key not in groups:
            groups[key] = {'sum': 0.0, 'max': 0.0, 'samples': set(),
                           'priorities': set(), 'states': {}, 'wait_reasons': {}}
        record = groups[key]
        rate = asfloat(row.get('SwitchesPerSec'))
        record['sum'] += rate
        record['max'] = max(record['max'], rate)
        record['samples'].add(row['Sample'])
        if row.get('PriorityCurrent', '') != '':
            record['priorities'].add(row['PriorityCurrent'])
        for field, keyname in (('ThreadState', 'states'), ('ThreadWaitReason', 'wait_reasons')):
            text = row.get(field, '')
            if text:
                record[keyname][text] = record[keyname].get(text, 0) + 1
    out = []
    for (pid, tid), v in groups.items():
        observed = len(v['samples'])
        out.append({
            'PID': pid, 'TID': tid, 'ProcessName': pid_to_name.get(pid, '<exited/unmapped>'),
            'SamplesSeen': observed, 'TotalSamples': count_all,
            'MeanSwitchesPerSec_Observed': round(v['sum'] / observed, 3),
            'MeanSwitchesPerSec_AllSamples': round(v['sum'] / count_all, 3),
            'MaxSwitchesPerSec': round(v['max'], 3),
            'PrioritiesSeen': ','.join(sorted(v['priorities'])),
            'StatesSeen': json.dumps(v['states'], sort_keys=True),
            'WaitReasonsSeen': json.dumps(v['wait_reasons'], sort_keys=True),
        })
    out.sort(key=lambda r: r['MeanSwitchesPerSec_AllSamples'], reverse=True)
    fields = ['PID', 'TID', 'ProcessName', 'SamplesSeen', 'TotalSamples',
              'MeanSwitchesPerSec_Observed', 'MeanSwitchesPerSec_AllSamples',
              'MaxSwitchesPerSec', 'PrioritiesSeen', 'StatesSeen', 'WaitReasonsSeen']
    write_csv(local / 'thread_switch_summary.csv', out, fields)


def compare_outputs(root, targets):
    a, b = targets
    la, lb = a['label'], b['label']
    dest = root / 'comparison'
    dest.mkdir(exist_ok=True)
    a_dir = root / 'runs' / la
    b_dir = root / 'runs' / lb
    p1 = {r['ProcessName']: r for r in read_csv(a_dir / 'windows' / 'Process_ByName_Averages.csv')}
    p2 = {r['ProcessName']: r for r in read_csv(b_dir / 'windows' / 'Process_ByName_Averages.csv')}
    processes = []
    for name in sorted(set(p1) | set(p2)):
        old = p1.get(name, {})
        new = p2.get(name, {})
        x, y = asfloat(old.get('AvgSwitchesPerSec')), asfloat(new.get('AvgSwitchesPerSec'))
        processes.append({'ProcessName': name, f'{la}_SwitchesPerSec': round(x, 3),
                          f'{lb}_SwitchesPerSec': round(y, 3), 'DeltaSwitchesPerSec': round(y-x, 3),
                          'DeltaPercent': round((y-x)/x*100, 2) if x else '',
                          f'{la}_CPUPercent': old.get('AvgCPUPercent_OfVM', ''),
                          f'{lb}_CPUPercent': new.get('AvgCPUPercent_OfVM', ''),
                          f'{la}_Present': bool(old), f'{lb}_Present': bool(new)})
    processes.sort(key=lambda row: abs(row['DeltaSwitchesPerSec']), reverse=True)
    fields = ['ProcessName', f'{la}_SwitchesPerSec', f'{lb}_SwitchesPerSec', 'DeltaSwitchesPerSec',
              'DeltaPercent', f'{la}_CPUPercent', f'{lb}_CPUPercent', f'{la}_Present', f'{lb}_Present']
    write_csv(dest / 'all_process_context_switch_deltas.csv', processes, fields)

    metrics = {}
    for label, directory in ((la, a_dir), (lb, b_dir)):
        for row in read_csv(directory / 'windows' / 'System_Averages.csv'):
            metrics.setdefault(row['Metric'], {})[label] = as_optional_float(row['Mean'])
    comparisons = []
    for name, m in sorted(metrics.items()):
        x, y = m.get(la), m.get(lb)
        comparisons.append({'Metric': name, la: x if x is not None else '', lb: y if y is not None else '',
                            'Delta': round(y-x, 4) if x is not None and y is not None else ''})
    write_csv(dest / 'windows_system_deltas.csv', comparisons, ['Metric', la, lb, 'Delta'])

    vc = {}
    for label, directory in ((la, a_dir), (lb, b_dir)):
        for row in read_csv(directory / 'vcenter' / 'summary_by_vm.csv'):
            vc.setdefault(row['metric'], {})[label] = as_optional_float(row.get('average_per_vcpu_percent'))
    vccomp = []
    for name, m in sorted(vc.items()):
        x, y = m.get(la), m.get(lb)
        vccomp.append({'Metric': name, la: x if x is not None else '', lb: y if y is not None else '',
                       'Delta_percentage_points': round(y-x, 4) if x is not None and y is not None else ''})
    write_csv(dest / 'vcenter_cpu_scheduling_deltas.csv', vccomp,
              ['Metric', la, lb, 'Delta_percentage_points'])

    print('\n=== Largest changes in process context switches/sec ===')
    for r in processes[:20]:
        print(f"  {r['ProcessName'][:32]:32} {r['DeltaSwitchesPerSec']:+12,.2f}/sec")
    print(f'\nSaved full all-process comparison: {dest / "all_process_context_switch_deltas.csv"}')


def main():
    args = parser()
    runid = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    root = Path(args.output or ('SchedulerComparison_' + runid)).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    vc_pass = os.getenv(args.vcenter_password_env) if args.vcenter_password_env else None
    if vc_pass is None:
        vc_pass = getpass.getpass('vCenter password: ')
    if not vc_pass:
        raise ValueError('A non-empty vCenter password is required')
    metadata = {'started_utc': iso(utc_now()), 'targets': args.target,
                'sample_count': args.samples, 'target_sample_interval_seconds': args.interval_seconds,
                'trace_etw': args.trace_etw, 'vcenter': args.vcenter,
                'collector_sha256': hashlib.sha256(COLLECTOR.read_bytes()).hexdigest(),
                'sample_windows_overlap': False}
    json_out(root / 'orchestrator_manifest.json', metadata)
    preflight_vcenter(args, vc_pass, root)
    for target in args.target:  # STRICTLY ONE WINDOWS TEST AT A TIME.
        first, last, manifest = windows_run(target, args, root)
        write_thread_summary(root / 'runs' / target['label'])
        vc_result = vcenter_run(target, args, root, vc_pass, first, last)
        label = target['label']
        mpath = root / 'runs' / label / 'run_manifest.json'
        manifest['vcenter'] = vc_result
        json_out(mpath, manifest)
    compare_outputs(root, args.target)
    metadata['finished_utc'] = iso(utc_now())
    json_out(root / 'orchestrator_manifest.json', metadata)
    bundle = root.parent / (root.name + '_shareable_results.zip')
    with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for filename in root.rglob('*'):
            if filename.is_file() and filename.suffix.lower() != '.etl':
                archive.write(filename, filename.relative_to(root))
    print(f'\nDONE: {root}')
    print(f'Consolidated shareable ZIP (ETLs excluded): {bundle}')
    print('NOTE: The Windows runs were sequential. Ensure both runs had equivalent steady-state load.')
    print('NOTE: Guest process switch attribution comes from performance counters; ETW is needed to prove switch reasons.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (KeyboardInterrupt, Exception) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
