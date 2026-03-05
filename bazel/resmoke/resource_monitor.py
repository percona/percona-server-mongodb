"""
Captures system and per-process metrics during test execution.
"""

import datetime
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import psutil

logger = logging.getLogger("resource_monitor")


@dataclass
class ResourceSnapshot:
    """Captures system and process tree state at a point in time."""

    timestamp: float
    duration_since_start: float
    system_metrics: dict[str, Any]
    process_tree: list[dict[str, Any]]
    all_processes_by_pid: dict[int, dict[str, Any]] = field(default_factory=dict)


class ProcessTreeMonitor:
    """Monitors a process and its descendants."""

    def __init__(self, root_pid: int):
        """Initialize process tree monitor.

        Args:
            root_pid: PID of the root process to monitor.
        """
        self.root_pid = root_pid
        try:
            self.root_process = psutil.Process(root_pid)
        except psutil.NoSuchProcess:
            logger.warning(f"Root process {root_pid} not found")
            self.root_process = None

    def collect_tree(self) -> list[dict[str, Any]]:
        """Collect metrics for all processes in the tree.

        Returns:
            List of process metric dictionaries.
        """
        if not self.root_process:
            return []

        try:
            # Get all descendant processes recursively
            children = self.root_process.children(recursive=True)
            all_procs = [self.root_process] + children

            process_list = []
            for proc in all_procs:
                try:
                    metrics = self._collect_process_metrics(proc)
                    if metrics:
                        process_list.append(metrics)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logger.debug(f"Could not collect metrics for process {proc.pid}: {e}")
                    continue

            return process_list
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Could not collect process tree for {self.root_pid}: {e}")
            return []

    def _collect_process_metrics(self, proc: psutil.Process) -> Optional[dict[str, Any]]:
        """Collect metrics for a single process.

        Args:
            proc: psutil.Process instance.

        Returns:
            Dictionary of process metrics, or None if collection failed.
        """
        try:
            with proc.oneshot():
                pid = proc.pid
                name = proc.name()
                status = proc.status()

                mem_info = proc.memory_info()
                memory_rss = mem_info.rss
                memory_vms = mem_info.vms

                cpu_percent = proc.cpu_percent(interval=0)

                try:
                    cpu_times = proc.cpu_times()
                    cpu_user_time = cpu_times.user
                    cpu_system_time = cpu_times.system
                except (psutil.AccessDenied, AttributeError):
                    cpu_user_time = None
                    cpu_system_time = None

                try:
                    io_counters = proc.io_counters()
                    io_read_count = io_counters.read_count
                    io_write_count = io_counters.write_count
                    io_read_bytes = io_counters.read_bytes
                    io_write_bytes = io_counters.write_bytes
                except (psutil.AccessDenied, AttributeError, NotImplementedError):
                    io_read_count = None
                    io_write_count = None
                    io_read_bytes = None
                    io_write_bytes = None

                try:
                    num_threads = proc.num_threads()
                except (psutil.AccessDenied, AttributeError):
                    num_threads = None

                try:
                    cmdline = proc.cmdline()
                    if cmdline:
                        cmdline_str = " ".join(cmdline)
                    else:
                        cmdline_str = f"[{name}]"
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    cmdline_str = f"[{name}]"

                try:
                    create_time = proc.create_time()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    create_time = None

                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    ppid = None

                return {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "status": status,
                    "cpu_percent": cpu_percent,
                    "cpu_user_time": cpu_user_time,
                    "cpu_system_time": cpu_system_time,
                    "memory_rss": memory_rss,
                    "memory_vms": memory_vms,
                    "num_threads": num_threads,
                    "io_read_count": io_read_count,
                    "io_write_count": io_write_count,
                    "io_read_bytes": io_read_bytes,
                    "io_write_bytes": io_write_bytes,
                    "cmdline": cmdline_str,
                    "create_time": create_time,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None


class ResourceMonitor:
    """Monitors total system resource usage"""

    PERIODIC_INTERVAL = 10  # seconds between periodic snapshots

    def __init__(self, output_file: str, root_pid: int):
        """Initialize resource monitor.

        Args:
            output_file: Path to output file for monitoring data.
            root_pid: PID of the resmoke_shim process to monitor.
        """
        self.output_file = output_file
        self.root_pid = root_pid
        self.start_time = time.time()
        self.process_tree_monitor = ProcessTreeMonitor(root_pid)

        # Threading for periodic monitoring
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        self.snapshots: list[ResourceSnapshot] = []

        # File lock for thread-safe writes
        self.file_lock = threading.Lock()

        # Initial system I/O counters for calculating deltas
        try:
            self.initial_disk_io = psutil.disk_io_counters()
            self.initial_net_io = psutil.net_io_counters()
        except Exception as e:
            logger.debug(f"Could not get initial I/O counters: {e}")
            self.initial_disk_io = None
            self.initial_net_io = None

    def collect_snapshot(self) -> ResourceSnapshot:
        """Collect a resource snapshot at the current moment."""
        timestamp = time.time()
        duration = timestamp - self.start_time

        system_metrics = self._collect_system_metrics()

        process_tree = self.process_tree_monitor.collect_tree()

        processes_by_pid = {p["pid"]: p for p in process_tree}

        snapshot = ResourceSnapshot(
            timestamp=timestamp,
            duration_since_start=duration,
            system_metrics=system_metrics,
            process_tree=process_tree,
            all_processes_by_pid=processes_by_pid,
        )

        self.snapshots.append(snapshot)
        return snapshot

    def _collect_system_metrics(self) -> dict[str, Any]:
        metrics = {}
        self._collect_cpu_metrics(metrics)
        self._collect_memory_metrics(metrics)
        self._collect_disk_io_metrics(metrics)
        self._collect_network_io_metrics(metrics)
        return metrics

    def _collect_cpu_metrics(self, metrics: dict[str, Any]):
        try:
            metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["cpu_count"] = psutil.cpu_count()
            metrics["cpu_count_logical"] = psutil.cpu_count(logical=True)
            metrics["cpu_count_physical"] = psutil.cpu_count(logical=False)
        except Exception as e:
            logger.debug(f"Could not collect CPU metrics: {e}")
            metrics["cpu_percent"] = None
            metrics["cpu_count"] = None
            metrics["cpu_count_logical"] = None
            metrics["cpu_count_physical"] = None

        try:
            if hasattr(os, "getloadavg"):
                load_avg = os.getloadavg()
                metrics["load_avg_1min"] = load_avg[0]
                metrics["load_avg_5min"] = load_avg[1]
                metrics["load_avg_15min"] = load_avg[2]
        except Exception as e:
            logger.debug(f"Could not collect load average: {e}")

    def _collect_memory_metrics(self, metrics: dict[str, Any]):
        try:
            mem = psutil.virtual_memory()
            metrics["memory_total"] = mem.total
            metrics["memory_available"] = mem.available
            metrics["memory_used"] = mem.used
            metrics["memory_free"] = mem.free
            metrics["memory_percent"] = mem.percent
        except Exception as e:
            logger.debug(f"Could not collect memory metrics: {e}")
            metrics["memory_total"] = None
            metrics["memory_available"] = None
            metrics["memory_used"] = None
            metrics["memory_percent"] = None

    def _collect_disk_io_metrics(self, metrics: dict[str, Any]):
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics["disk_read_bytes"] = disk_io.read_bytes
                metrics["disk_write_bytes"] = disk_io.write_bytes
                metrics["disk_read_count"] = disk_io.read_count
                metrics["disk_write_count"] = disk_io.write_count
                metrics["disk_read_time"] = disk_io.read_time
                metrics["disk_write_time"] = disk_io.write_time
                metrics["disk_busy_time"] = (
                    disk_io.busy_time if hasattr(disk_io, "busy_time") else None
                )
            else:
                metrics["disk_read_bytes"] = None
                metrics["disk_write_bytes"] = None
                metrics["disk_read_count"] = None
                metrics["disk_write_count"] = None
                metrics["disk_read_time"] = None
                metrics["disk_write_time"] = None
                metrics["disk_busy_time"] = None
        except Exception as e:
            logger.debug(f"Could not collect disk I/O metrics: {e}")
            metrics["disk_read_bytes"] = None
            metrics["disk_write_bytes"] = None
            metrics["disk_read_count"] = None
            metrics["disk_write_count"] = None
            metrics["disk_read_time"] = None
            metrics["disk_write_time"] = None
            metrics["disk_busy_time"] = None

        try:
            disk_io_per_disk = psutil.disk_io_counters(perdisk=True)
            if disk_io_per_disk:
                metrics["disk_io_per_disk"] = {
                    disk: {
                        "read_bytes": counters.read_bytes,
                        "write_bytes": counters.write_bytes,
                        "read_count": counters.read_count,
                        "write_count": counters.write_count,
                    }
                    for disk, counters in disk_io_per_disk.items()
                }
        except Exception as e:
            logger.debug(f"Could not collect per-disk I/O metrics: {e}")

    def _collect_network_io_metrics(self, metrics: dict[str, Any]):
        try:
            net_io = psutil.net_io_counters()
            if net_io:
                metrics["network_sent_bytes"] = net_io.bytes_sent
                metrics["network_recv_bytes"] = net_io.bytes_recv
                metrics["network_sent_packets"] = net_io.packets_sent
                metrics["network_recv_packets"] = net_io.packets_recv
            else:
                metrics["network_sent_bytes"] = None
                metrics["network_recv_bytes"] = None
                metrics["network_sent_packets"] = None
                metrics["network_recv_packets"] = None
        except Exception as e:
            logger.debug(f"Could not collect network I/O metrics: {e}")
            metrics["network_sent_bytes"] = None
            metrics["network_recv_bytes"] = None
            metrics["network_sent_packets"] = None
            metrics["network_recv_packets"] = None

        try:
            net_io_per_nic = psutil.net_io_counters(pernic=True)
            if net_io_per_nic:
                metrics["network_io_per_interface"] = {
                    iface: {
                        "sent_bytes": counters.bytes_sent,
                        "recv_bytes": counters.bytes_recv,
                        "sent_packets": counters.packets_sent,
                        "recv_packets": counters.packets_recv,
                    }
                    for iface, counters in net_io_per_nic.items()
                }
        except Exception as e:
            logger.debug(f"Could not collect per-interface network metrics: {e}")

    def write_snapshot(self, snapshot: ResourceSnapshot):
        """Write a snapshot to the output file."""
        output = self._format_snapshot(snapshot)
        with self.file_lock:
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(output)
                f.write("\n")

    def _format_snapshot(self, snapshot: ResourceSnapshot) -> str:
        """Format a snapshot as human-readable text."""
        lines = []
        self._format_header(lines, snapshot)
        lines.append("System Metrics:")

        sm = snapshot.system_metrics
        self._format_cpu_metrics(lines, sm)
        self._format_memory_metrics(lines, sm)
        self._format_disk_io_metrics(lines, sm, snapshot.duration_since_start)
        self._format_network_io_metrics(lines, sm)
        self._format_process_tree_section(lines, snapshot)

        return "\n".join(lines)

    def _format_header(self, lines: list[str], snapshot: ResourceSnapshot):
        """Format snapshot header with timestamp."""
        timestamp_str = datetime.datetime.fromtimestamp(snapshot.timestamp).strftime("%H:%M:%S")
        header = f"=== {timestamp_str} | T+{snapshot.duration_since_start:.1f}s ==="
        padding_needed = 80 - len(header)
        if padding_needed > 0:
            header += "=" * padding_needed
        lines.append(header)

    def _format_cpu_metrics(self, lines: list[str], sm: dict[str, Any]):
        """Format CPU metrics section."""
        if sm.get("cpu_percent") is not None:
            lines.append(f"  CPU Usage:        {sm['cpu_percent']:.1f}%")
            if sm.get("cpu_count_logical") and sm.get("cpu_count_physical"):
                lines.append(
                    f"  CPU Cores:        {sm['cpu_count_physical']} physical, "
                    f"{sm['cpu_count_logical']} logical"
                )
            elif sm.get("cpu_count"):
                lines.append(f"  CPU Cores:        {sm['cpu_count']}")

        if sm.get("load_avg_1min") is not None:
            lines.append(
                f"  Load Average:     {sm['load_avg_1min']:.2f} (1m), "
                f"{sm['load_avg_5min']:.2f} (5m), {sm['load_avg_15min']:.2f} (15m)"
            )

    def _format_memory_metrics(self, lines: list[str], sm: dict[str, Any]):
        """Format memory and swap metrics section."""
        if sm.get("memory_total") is not None:
            mem_total_gb = sm["memory_total"] / (1024**3)
            mem_avail_gb = sm["memory_available"] / (1024**3)
            mem_used_gb = sm["memory_used"] / (1024**3)
            mem_free_gb = sm.get("memory_free", 0) / (1024**3)
            lines.append(f"  Memory Total:     {mem_total_gb:.1f} GB")
            lines.append(
                f"  Memory Used:      {mem_used_gb:.1f} GB ({sm['memory_percent']:.1f}%) | "
                f"Available: {mem_avail_gb:.1f} GB | Free: {mem_free_gb:.1f} GB"
            )

    def _format_disk_io_metrics(self, lines: list[str], sm: dict[str, Any], duration: float):
        """Format disk I/O metrics section."""
        disk_read_bytes = sm.get("disk_read_bytes")
        disk_write_bytes = sm.get("disk_write_bytes")
        disk_read_count = sm.get("disk_read_count")
        disk_write_count = sm.get("disk_write_count")
        disk_read_time = sm.get("disk_read_time")
        disk_write_time = sm.get("disk_write_time")
        disk_busy_time = sm.get("disk_busy_time")

        if (
            self.initial_disk_io
            and disk_read_bytes is not None
            and disk_write_bytes is not None
            and disk_read_count is not None
            and disk_write_count is not None
            and disk_read_time is not None
            and disk_write_time is not None
        ):
            disk_read_delta = (disk_read_bytes - self.initial_disk_io.read_bytes) / (1024**2)
            disk_write_delta = (disk_write_bytes - self.initial_disk_io.write_bytes) / (1024**2)
            disk_read_count_delta = disk_read_count - self.initial_disk_io.read_count
            disk_write_count_delta = disk_write_count - self.initial_disk_io.write_count
            disk_read_time_delta = disk_read_time - self.initial_disk_io.read_time
            disk_write_time_delta = disk_write_time - self.initial_disk_io.write_time

            if duration > 0:
                read_mb_per_sec = disk_read_delta / duration
                write_mb_per_sec = disk_write_delta / duration
                read_ops_per_sec = disk_read_count_delta / duration
                write_ops_per_sec = disk_write_count_delta / duration

                lines.append(
                    f"  Disk I/O Read:    {disk_read_delta:.1f} MB "
                    f"({disk_read_count_delta:,} ops, {read_mb_per_sec:.1f} MB/s, "
                    f"{read_ops_per_sec:.1f} ops/s)"
                )
                lines.append(
                    f"  Disk I/O Write:   {disk_write_delta:.1f} MB "
                    f"({disk_write_count_delta:,} ops, {write_mb_per_sec:.1f} MB/s, "
                    f"{write_ops_per_sec:.1f} ops/s)"
                )

                if disk_read_count_delta > 0:
                    avg_read_wait = disk_read_time_delta / disk_read_count_delta
                    avg_read_size_kb = (disk_read_delta * 1024) / disk_read_count_delta
                    lines.append(
                        f"  Disk Read Stats:  avg wait {avg_read_wait:.1f} ms, "
                        f"avg size {avg_read_size_kb:.1f} KB"
                    )

                if disk_write_count_delta > 0:
                    avg_write_wait = disk_write_time_delta / disk_write_count_delta
                    avg_write_size_kb = (disk_write_delta * 1024) / disk_write_count_delta
                    lines.append(
                        f"  Disk Write Stats: avg wait {avg_write_wait:.1f} ms, "
                        f"avg size {avg_write_size_kb:.1f} KB"
                    )

                if (
                    disk_busy_time is not None
                    and hasattr(self.initial_disk_io, "busy_time")
                    and self.initial_disk_io.busy_time is not None
                ):
                    busy_delta = disk_busy_time - self.initial_disk_io.busy_time
                    utilization = min(100.0, (busy_delta / (duration * 1000)) * 100)
                    lines.append(f"  Disk Utilization: {utilization:.1f}%")
            else:
                lines.append(
                    f"  Disk I/O Read:    {disk_read_delta:.1f} MB ({disk_read_count_delta:,} ops)"
                )
                lines.append(
                    f"  Disk I/O Write:   {disk_write_delta:.1f} MB "
                    f"({disk_write_count_delta:,} ops)"
                )

    def _format_network_io_metrics(self, lines: list[str], sm: dict[str, Any]):
        """Format network I/O metrics section."""
        net_sent_bytes = sm.get("network_sent_bytes")
        net_recv_bytes = sm.get("network_recv_bytes")
        net_sent_packets = sm.get("network_sent_packets")
        net_recv_packets = sm.get("network_recv_packets")

        if (
            self.initial_net_io
            and net_sent_bytes is not None
            and net_recv_bytes is not None
            and net_sent_packets is not None
            and net_recv_packets is not None
        ):
            net_sent_delta = (net_sent_bytes - self.initial_net_io.bytes_sent) / (1024**2)
            net_recv_delta = (net_recv_bytes - self.initial_net_io.bytes_recv) / (1024**2)
            net_sent_packets_delta = net_sent_packets - self.initial_net_io.packets_sent
            net_recv_packets_delta = net_recv_packets - self.initial_net_io.packets_recv
            lines.append(
                f"  Network Sent:     {net_sent_delta:.1f} MB ({net_sent_packets_delta:,} packets)"
            )
            lines.append(
                f"  Network Received: {net_recv_delta:.1f} MB ({net_recv_packets_delta:,} packets)"
            )

    def _format_process_tree_section(self, lines: list[str], snapshot: ResourceSnapshot):
        """Format process tree section."""
        process_count = len(snapshot.process_tree)
        lines.append("Process Tree:")

        if process_count == 0:
            lines.append("  No processes found")
        else:
            procs_by_pid = snapshot.all_processes_by_pid
            procs_by_ppid = {}
            for proc in snapshot.process_tree:
                ppid = proc["ppid"]
                if ppid not in procs_by_ppid:
                    procs_by_ppid[ppid] = []
                procs_by_ppid[ppid].append(proc)

            self._format_process_tree(
                lines, self.root_pid, procs_by_pid, procs_by_ppid, prefix="", is_last=True
            )

    def _format_process_tree(
        self,
        lines: list[str],
        pid: int,
        procs_by_pid: dict[int, dict],
        procs_by_ppid: dict[int, list[dict]],
        prefix: str = "",
        is_last: bool = True,
    ):
        """Recursively format process tree with tree-style formatting.

        Args:
            lines: List to append formatted lines to.
            pid: PID of process to format.
            procs_by_pid: Dictionary mapping PID to process info.
            procs_by_ppid: Dictionary mapping parent PID to list of children.
            prefix: Current line prefix for tree drawing.
            is_last: Whether this is the last child of its parent.
        """
        proc = procs_by_pid.get(pid)
        if not proc:
            return

        mem_rss_mb = proc["memory_rss"] / (1024**2)
        cmdline = proc["cmdline"]

        if prefix == "":
            process_header = f"[{proc['pid']}] {proc['name']}"
            detail_prefix = "   │  "
        else:
            tree_char = "└─" if is_last else "├─"
            process_header = f"{prefix}{tree_char}[{proc['pid']}] {proc['name']}"
            continuation = "    " if is_last else "│   "
            detail_prefix = prefix + continuation

        lines.append(process_header)

        cpu_line = f"{detail_prefix}CPU: {proc['cpu_percent']:.1f}%"
        if proc["cpu_user_time"] is not None and proc["cpu_system_time"] is not None:
            cpu_line += (
                f" (user: {proc['cpu_user_time']:.1f}s, sys: {proc['cpu_system_time']:.1f}s)"
            )
        cpu_line += (
            f" | Mem (RSS): {mem_rss_mb:.1f}MB | Threads: {proc['num_threads']} | {proc['status']}"
        )
        lines.append(cpu_line)

        if proc["io_read_bytes"] is not None and proc["io_write_bytes"] is not None:
            io_read_mb = proc["io_read_bytes"] / (1024**2)
            io_write_mb = proc["io_write_bytes"] / (1024**2)
            lines.append(
                f"{detail_prefix}I/O: R {io_read_mb:.1f}MB ({proc['io_read_count']:,} ops), "
                f"W {io_write_mb:.1f}MB ({proc['io_write_count']:,} ops)"
            )

        lines.append(f"{detail_prefix}Cmd: {cmdline}")

        children = procs_by_ppid.get(pid, [])
        if children:
            child_prefix = "   " if prefix == "" else prefix + ("    " if is_last else "│   ")
            sorted_children = sorted(children, key=lambda p: p["pid"])
            for i, child in enumerate(sorted_children):
                is_last_child = i == len(sorted_children) - 1
                self._format_process_tree(
                    lines, child["pid"], procs_by_pid, procs_by_ppid, child_prefix, is_last_child
                )

    def start_periodic_monitoring(self):
        """Start periodic monitoring in a background thread."""
        if self.monitoring_thread is not None:
            logger.warning("Periodic monitoring already started")
            return

        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(
            target=self._periodic_monitoring_loop, daemon=True, name="ResourceMonitor"
        )
        self.monitoring_thread.start()
        logger.debug("Started periodic resource monitoring")

    def stop_periodic_monitoring(self):
        """Stop periodic monitoring thread."""
        if self.monitoring_thread is None:
            return

        self.stop_event.set()
        self.monitoring_thread.join(timeout=self.PERIODIC_INTERVAL + 5)
        if self.monitoring_thread.is_alive():
            logger.warning("Periodic monitoring thread did not stop gracefully")
        else:
            logger.debug("Stopped periodic resource monitoring")
        self.monitoring_thread = None

    def _periodic_monitoring_loop(self):
        """Background thread loop for periodic monitoring."""
        try:
            while not self.stop_event.wait(self.PERIODIC_INTERVAL):
                try:
                    snapshot = self.collect_snapshot()
                    self.write_snapshot(snapshot)
                except Exception as e:
                    logger.error(f"Error in periodic monitoring: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Fatal error in periodic monitoring loop: {e}", exc_info=True)
