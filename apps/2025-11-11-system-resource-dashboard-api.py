import os
import time
import psutil
from typing import Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_io: Dict[str, float]
    network_io: Dict[str, float]

app = FastAPI()

@app.get("/metrics", response_model=SystemMetrics)
def get_system_metrics():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        disk_io = psutil.disk_io_counters(perdisk=True)
        network_io = psutil.net_io_counters(pernic=True)

        return SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_io={device: (disk_io[device].read_bytes, disk_io[device].write_bytes) for device in disk_io},
            network_io={interface: (network_io[interface].bytes_sent, network_io[interface].bytes_recv) for interface in network_io}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def get_cpu_utilization():
    """
    Retrieves the current CPU utilization percentage.
    
    Returns:
        float: The current CPU utilization percentage.
    """
    return psutil.cpu_percent(interval=1)

def get_memory_utilization():
    """
    Retrieves the current memory utilization percentage.
    
    Returns:
        float: The current memory utilization percentage.
    """
    return psutil.virtual_memory().percent

def get_disk_io_stats():
    """
    Retrieves the current disk I/O statistics.
    
    Returns:
        dict: A dictionary containing the read and write bytes for each disk device.
    """
    disk_io = psutil.disk_io_counters(perdisk=True)
    return {device: (disk_io[device].read_bytes, disk_io[device].write_bytes) for device in disk_io}

def get_network_io_stats():
    """
    Retrieves the current network I/O statistics.
    
    Returns:
        dict: A dictionary containing the bytes sent and received for each network interface.
    """
    network_io = psutil.net_io_counters(pernic=True)
    return {interface: (network_io[interface].bytes_sent, network_io[interface].bytes_recv) for interface in network_io}

def get_system_uptime():
    """
    Retrieves the current system uptime.
    
    Returns:
        float: The current system uptime in seconds.
    """
    return time.time() - psutil.boot_time()

def get_system_load_average():
    """
    Retrieves the current system load average.
    
    Returns:
        tuple: A tuple containing the 1-minute, 5-minute, and 15-minute load averages.
    """
    return os.getloadavg()

def get_system_temperature():
    """
    Retrieves the current system temperature.
    
    Returns:
        float: The current system temperature in degrees Celsius.
    """
    try:
        temps = psutil.sensors_temperatures()
        for name, entries in temps.items():
            for entry in entries:
                if 'coretemp' in name.lower():
                    return entry.current
    except (AttributeError, IndexError):
        return None

def get_system_fan_speeds():
    """
    Retrieves the current system fan speeds.
    
    Returns:
        dict: A dictionary containing the fan name and speed for each fan.
    """
    try:
        fans = psutil.sensors_fans()
        return {name: entry.current for name, entries in fans.items() for entry in entries}
    except (AttributeError, IndexError):
        return {}

def get_system_battery_status():
    """
    Retrieves the current system battery status.
    
    Returns:
        dict: A dictionary containing the battery percent, power plugged in status, and battery time remaining.
    """
    try:
        battery = psutil.sensors_battery()
        return {
            'percent': battery.percent,
            'power_plugged': battery.power_plugged,
            'time_remaining': battery.secsleft
        }
    except (AttributeError, IndexError):
        return {
            'percent': None,
            'power_plugged': None,
            'time_remaining': None
        }

def get_system_disk_usage():
    """
    Retrieves the current system disk usage.
    
    Returns:
        dict: A dictionary containing the total, used, and free disk space for each mounted partition.
    """
    disk_usage = {}
    for partition in psutil.disk_partitions():
        if os.name == 'nt':
            if 'cdrom' in partition.opts or partition.fstype == '':
                continue
        usage = psutil.disk_usage(partition.mountpoint)
        disk_usage[partition.mountpoint] = {
            'total': usage.total,
            'used': usage.used,
            'free': usage.free
        }
    return disk_usage

def get_system_network_interfaces():
    """
    Retrieves the current system network interfaces.
    
    Returns:
        dict: A dictionary containing the name, address, netmask, and broadcast address for each network interface.
    """
    network_interfaces = {}
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_INET:
                network_interfaces[interface] = {
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                }
    return network_interfaces

def get_system_processes():
    """
    Retrieves the current system processes.
    
    Returns:
        list: A list of dictionaries containing information about each running process.
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            process_info = proc.info
            processes.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes

def get_system_users():
    """
    Retrieves the current system users.
    
    Returns:
        list: A list of dictionaries containing information about each logged-in user.
    """
    users = []
    for user in psutil.users():
        users.append({
            'username': user.name,
            'terminal': user.terminal,
            'host': user.host,
            'started': user.started
        })
    return users

def get_system_services():
    """
    Retrieves the current system services.
    
    Returns:
        list: A list of dictionaries containing information about each running service.
    """
    services = []
    for service in psutil.win_service_iter():
        try:
            service_info = service.as_dict()
            services.append(service_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return services

def get_system_event_logs():
    """
    Retrieves the current system event logs.
    
    Returns:
        list: A list of dictionaries containing information about each event log entry.
    """
    event_logs = []
    for log in psutil.win_eventlog('Application'):
        event_logs.append({
            'source': log.source,
            'eventid': log.eventid,
            'message': log.message,
            'timestamp': log.created
        })
    return event_logs

def get_system_startup_programs():
    """
    Retrieves the current system startup programs.
    
    Returns:
        list: A list of dictionaries containing information about each startup program.
    """
    startup_programs = []
    for program in psutil.win_startup_info():
        startup_programs.append({
            'name': program.name,
            'path': program.path,
            'args': program.args,
            'username': program.username,
            'location': program.location
        })
    return startup_programs

def get_system_scheduled_tasks():
    """
    Retrieves the current system scheduled tasks.
    
    Returns:
        list: A list of dictionaries containing information about each scheduled task.
    """
    scheduled_tasks = []
    for task in psutil.win_task_list():
        scheduled_tasks.append({
            'name': task.name,
            'task_id': task.task_id,
            'user_name': task.user_name,
            'next_run_time': task.next_run_time,
            'status': task.status
        })
    return scheduled_tasks

def get_system_installed_software():
    """
    Retrieves the current system installed software.
    
    Returns:
        list: A list of dictionaries containing information about each installed software.
    """
    installed_software = []
    for software in psutil.win_software_list():
        installed_software.append({
            'name': software.name,
            'version': software.version,
            'publisher': software.publisher,
            'install_date': software.install_date
        })
    return installed_software

def get_system_network_connections():
    """
    Retrieves the current system network connections.
    
    Returns:
        list: A list of dictionaries containing information about each network connection.
    """
    network_connections = []
    for conn in psutil.net_connections():
        network_connections.append({
            'fd': conn.fd,
            'family': conn.family,
            'type': conn.type,
            'local_address': conn.laddr,
            'remote_address': conn.raddr,
            'status': conn.status,
            'pid': conn.pid
        })
    return network_connections

def get_system_firewall_rules():
    """
    Retrieves the current system firewall rules.
    
    Returns:
        list: A list of dictionaries containing information about each firewall rule.
    """
    firewall_rules = []
    for rule in psutil.win_firewall_rules():
        firewall_rules.append({
            'name': rule.name,
            'description': rule.description,
            'app_path': rule.app_path,
            'protocol': rule.protocol,
            'local_ports': rule.local_ports,
            'remote_ports': rule.remote_ports,
            'direction': rule.direction,
            'action': rule.action,
            'profile': rule.profile,
            'grouping': rule.grouping,
            'enabled': rule.enabled
        })
    return firewall_rules

def get_system_registry_keys():
    """
    Retrieves the current system registry keys.
    
    Returns:
        list: A list of dictionaries containing information about each registry key.
    """
    registry_keys = []
    for key in psutil.win_registry_keys():
        registry_keys.append({
            'key': key.key,
            'value': key.value,
            'data': key.data,
            'type': key.type
        })
    return registry_keys

def get_system_drivers():
    """
    Retrieves the current system drivers.
    
    Returns:
        list: A list of dictionaries containing information about each driver.
    """
    drivers = []
    for driver in psutil.win_drivers():
        drivers.append({
            'name': driver.name,
            'description': driver.description,
            'status': driver.status,
            'start_mode': driver.start_mode,
            'path': driver.path
        })
    return drivers

def get_system_services_status():
    """
    Retrieves the current status of system services.
    
    Returns:
        dict: A dictionary containing the status of each service.
    """
    services_status = {}
    for service in psutil.win_service_iter():
        try:
            service_info = service.as_dict()
            services_status[service_info['name']] = service_info['status']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return services_status

def get_system_environment_variables():
    """
    Retrieves the current system environment variables.
    
    Returns:
        dict: A dictionary containing the system environment variables.
    """
    return dict(os.environ)

def get_system_performance_counters():
    """
    Retrieves the current system performance counters.
    
    Returns:
        dict: A dictionary containing the system performance counters.
    """
    performance_counters = {}
    for counter in psutil.win_perf_counters():
        performance_counters[counter.path] = counter.value
    return performance_counters

def get_system_power_plans():
    """
    Retrieves the current system power plans.
    
    Returns:
        list: A list of dictionaries containing information about each power plan.
    """
    power_plans = []
    for plan in psutil.win_power_options():
        power_plans.append({
            'name': plan.name,
            'guid': plan.guid,
            'description': plan.description,
            'active': plan.active
        })
    return power_plans

def get_system_network_adapters():
    """
    Retrieves the current system network adapters.
    
    Returns:
        list: A list of dictionaries containing information about each network adapter.
    """
    network_adapters = []
    for adapter in psutil.net_if_stats():
        network_adapters.append({
            'name': adapter,
            'isup': psutil.net_if_stats()[adapter].isup,
            'duplex': psutil.net_if_stats()[adapter].duplex,
            'speed': psutil.net_if_stats()[adapter].speed,
            'mtu': psutil.net_if_stats()[adapter].mtu
        })
    return network_adapters

def get_system_network_protocols():
    """
    Retrieves the current system network protocols.
    
    Returns:
        list: A list of dictionaries containing information about each network protocol.
    """
    network_protocols = []
    for protocol in psutil.net_connections():
        network_protocols.append({
            'family': protocol.family,
            'type': protocol.type,
            'local_address': protocol.laddr,
            'remote_address': protocol.raddr,
            'status': protocol.status,
            'pid': protocol.pid
        })
    return network_protocols

def get_system_disk_partitions():
    """
    Retrieves the current system disk partitions.
    
    Returns:
        list: A list of dictionaries containing information about each disk partition.
    """
    disk_partitions = []
    for partition in psutil.disk_partitions():
        disk_partitions.append({
            'device': partition.device,
            'mountpoint': partition.mountpoint,
            'fstype': partition.fstype,
            'opts': partition.opts
        })
    return disk_partitions

def get_system_disk_sensors():
    """
    Retrieves the current system disk sensors.
    
    Returns:
        dict: A dictionary containing the temperature and health status for each disk.
    """
    disk_sensors = {}
    for disk in psutil.disk_io_counters(perdisk=True):
        try:
            disk_sensors[disk] = {
                'temperature': psutil.sensors_temperatures()[disk][0].current,
                'health': psutil.disk_smart_info()[disk].health_status
            }
            except (AttributeError, IndexError, KeyError):
                disk_sensors[disk] = {
                    'temperature': None,
                    'health': 'Unknown'
                }
        return disk_sensors
