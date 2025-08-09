import subprocess
import requests
import time
import os
import zipfile
import socket
import psutil
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import configparser
import logging
import json
import threading
import traceback

def check_sudo_privileges():
    """Check if script is running with sudo/root privileges"""
    if os.geteuid() != 0:
        print("❌ ERROR: This script requires sudo/root privileges to run tcpdump")
        print("Please run the script with sudo:")
        print("   sudo ./troubleshoot-wt")
        print()
        print("Why sudo is needed:")
        print("  - tcpdump requires root privileges to capture network packets")
        print("  - Reading eti log files from /opt directories may require elevated access")
        return False
    return True

import subprocess

def check_tcpdump_availability():
    """Check if tcpdump is available and working"""
    try:
        # Check if tcpdump exists
        result = subprocess.run(
            ['which', 'tcpdump'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            print("❌ tcpdump not found. Please install it:")
            print("   Ubuntu/Debian: sudo apt install tcpdump")
            print("   CentOS/RHEL:   sudo yum install tcpdump")
            return False

        # Check if tcpdump can run
        result = subprocess.run(
            ['tcpdump', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            print("❌ tcpdump is installed but not working properly:")
            err_output = (result.stderr or result.stdout).strip()
            if err_output:
                print(f"   Error message from tcpdump: {err_output}")
            else:
                print("   No error message provided by tcpdump.")

            # Optional: suggest checking missing libraries
            print("\n💡 Hint: You can check missing dependencies with:")
            print("   ldd $(which tcpdump)")
            return False

        print("✅ tcpdump is available and working")
        return True

    except subprocess.TimeoutExpired:
        print("❌ tcpdump check timed out")
        return False
    except Exception as e:
        print(f"❌ Unexpected error while checking tcpdump: {e}")
        return False

def check_system_requirements():
    """Comprehensive system requirements check"""
    print("🔍 Checking system requirements...")
    print("=" * 50)
    
    requirements_met = True
    
    # 1. Check sudo privileges
    print("1. Checking sudo privileges...")
    if not check_sudo_privileges():
        requirements_met = False
    else:
        print("✅ Running with sudo/root privileges")
    
    # 2. Check tcpdump
    print("\n2. Checking tcpdump availability...")
    tcpdump_available = check_tcpdump_availability()
    if not tcpdump_available:
        requirements_met = False
    
    # 3. Check Python modules
    print("\n3. Checking Python modules...")
    required_modules = [
        'requests', 'psutil', 'configparser', 
        'apscheduler', 'urllib.parse'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module.split('.')[0])
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            missing_modules.append(module)
            requirements_met = False
    
    if missing_modules:
        print(f"\nInstall missing modules with:")
        print(f"   pip install {' '.join(missing_modules)}")
    
    # 4. Check config file
    print("\n4. Checking configuration file...")
    config_path = "/opt/watchdog/watchdog/watchdog.conf"
    if os.path.exists(config_path):
        print(f"✅ Config file found: {config_path}")
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            proxy_mode = config.getboolean('proxy', 'proxy_mode', fallback=False)
            print(f"✅ Config readable, proxy_mode: {proxy_mode}")
        except Exception as e:
            print(f"⚠️  Config file exists but has issues: {e}")
    else:
        print(f"⚠️  Config file not found: {config_path}")
        print("    Script will use fallback values")
    
    # 5. Check network connectivity
    print("\n5. Testing basic network connectivity...")
    try:
        response = requests.get('http://httpbin.org/ip', timeout=10)
        print("✅ Basic internet connectivity working")
    except Exception as e:
        print(f"⚠️  Network connectivity issue: {e}")
        print("    This may affect download tests")
    
    print("=" * 50)
    
    if requirements_met and tcpdump_available:
        print("🎉 All requirements met! Script can run with full functionality.")
        return True, True
    elif requirements_met:
        print("⚠️  Requirements met but tcpdump unavailable.")
        print("    Script will run with limited functionality (no packet capture).")
        return True, False
    else:
        print("❌ Critical requirements not met. Please fix the above issues.")
        return False, False

# Create temporary directory for files before zipping
TEMP_DIR = 'temp_capture'
os.makedirs(TEMP_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
# Log file for this script
SCRIPT_LOG_FILE = os.path.join(TEMP_DIR, 'troubleshoot.log')
file_handler = logging.FileHandler(SCRIPT_LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
))
logger.addHandler(file_handler)

# Configuration
PHISHTANK_URL = 'http://data.phishtank.com/data/online-valid.csv.bz2'
URLHAUS_URL = 'https://urlhaus.abuse.ch/downloads/csv/'
CONFIG_PATH = "/opt/watchdog/watchdog/watchdog.conf"

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

# Read proxy settings from config 
proxy_mode = config.getboolean('proxy', 'proxy_mode', fallback=False)
http_proxy = config.get('proxy', 'http_proxy', fallback='').strip()
https_proxy = config.get('proxy', 'https_proxy', fallback='').strip()

if proxy_mode:
    proxies = {}
    if http_proxy:
        proxies['http'] = http_proxy
    if https_proxy:
        proxies['https'] = https_proxy

    if not proxies:
        raise ValueError("Proxy mode enabled but no valid proxy URLs found in config.")
    
    logger.info(f"Proxies enabled: {proxies}")
else:
    proxies = None
    logger.info("Proxy disabled")

from urllib.parse import urlparse

PROXY_IP = None
PROXY_PORT = None

if proxy_mode:
    proxy_url = http_proxy or https_proxy
    if proxy_url:
        parsed = urlparse(proxy_url)
        PROXY_IP = parsed.hostname
        PROXY_PORT = parsed.port

        if not PROXY_IP or not PROXY_PORT:
            raise ValueError(f"Invalid proxy URL: {proxy_url}")
    else:
        raise ValueError("Proxy mode is enabled but no proxy URL found.")

# Global variables
job_executed = False
MAX_RETRIES = 3
RETRY_DELAY = 30
TCPDUMP_AVAILABLE = False  # Will be set by requirements check

def get_system_diagnostics():
    """Capture comprehensive system diagnostics"""
    diagnostics = {
        'timestamp': datetime.now().isoformat(),
        'system_info': {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'available_memory_mb': psutil.virtual_memory().available / (1024*1024),
            'disk_usage_percent': psutil.disk_usage('/').percent,
            'load_average': os.getloadavg(),
            'uptime_seconds': time.time() - psutil.boot_time()
        },
        'network_info': {
            'active_connections': len(psutil.net_connections()),
            'network_io': dict(psutil.net_io_counters()._asdict()),
        }
    }
    
    # Get network interface details
    try:
        interfaces = {}
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = [addr._asdict() for addr in addrs]
        diagnostics['network_interfaces'] = interfaces
    except Exception as e:
        diagnostics['network_interfaces_error'] = str(e)
    
    return diagnostics

def test_proxy_connectivity():
    """Test proxy connectivity with detailed diagnostics"""
    connectivity_test = {
        'timestamp': datetime.now().isoformat(),
        'proxy_ip': PROXY_IP,
        'proxy_port': PROXY_PORT,
        'tests': {}
    }
    
    # Test 1: Basic socket connection to proxy
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        start_time = time.time()
        result = sock.connect_ex((PROXY_IP, PROXY_PORT))
        end_time = time.time()
        sock.close()
        
        connectivity_test['tests']['socket_connect'] = {
            'success': result == 0,
            'result_code': result,
            'response_time_ms': (end_time - start_time) * 1000,
            'error': None if result == 0 else f"Connection failed with code {result}"
        }
    except Exception as e:
        connectivity_test['tests']['socket_connect'] = {
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }
    
    # Test 2: HTTP request through proxy with detailed timing
    try:
        start_time = time.time()
        response = requests.get(
            'http://httpbin.org/ip',
            proxies=proxies,
            timeout=30,
            verify=False
        )
        end_time = time.time()
        
        connectivity_test['tests']['http_request'] = {
            'success': True,
            'status_code': response.status_code,
            'response_time_ms': (end_time - start_time) * 1000,
            'response_content': response.text[:500],  # First 500 chars
            'headers': dict(response.headers)
        }
    except Exception as e:
        connectivity_test['tests']['http_request'] = {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'traceback': traceback.format_exc()
        }
    
    # Test 3: DNS resolution
    try:
        start_time = time.time()
        socket.gethostbyname(PROXY_IP if not PROXY_IP.replace('.', '').isdigit() else 'google.com')
        end_time = time.time()
        
        connectivity_test['tests']['dns_resolution'] = {
            'success': True,
            'response_time_ms': (end_time - start_time) * 1000
        }
    except Exception as e:
        connectivity_test['tests']['dns_resolution'] = {
            'success': False,
            'error': str(e)
        }
    
    return connectivity_test

def get_process_info():
    """Get information about current process and related processes"""
    process_info = {
        'timestamp': datetime.now().isoformat(),
        'current_process': {
            'pid': os.getpid(),
            'memory_info': psutil.Process().memory_info()._asdict(),
            'cpu_percent': psutil.Process().cpu_percent(),
            'open_files': len(psutil.Process().open_files()),
            'connections': len(psutil.Process().connections()),
            'threads': psutil.Process().num_threads()
        },
        'related_processes': []
    }
    
    # Look for related processes (tcpdump, proxy-related, etc.)
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info']):
            try:
                if any(keyword in ' '.join(proc.info['cmdline'] or []).lower() 
                      for keyword in ['tcpdump', 'proxy', 'squid', 'watchdog']):
                    process_info['related_processes'].append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cmdline': proc.info['cmdline'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_mb': proc.info['memory_info'].rss / (1024*1024) if proc.info['memory_info'] else 0
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        process_info['related_processes_error'] = str(e)
    
    return process_info

def get_scheduler_context():
    """Get information about the scheduler context when running"""
    context = {
        'timestamp': datetime.now().isoformat(),
        'is_main_thread': threading.current_thread() is threading.main_thread(),
        'thread_name': threading.current_thread().name,
        'active_thread_count': threading.active_count(),
        'thread_names': [t.name for t in threading.enumerate()]
    }
    return context

def download_with_retry(url, retries=MAX_RETRIES):
    attempt = 0
    detailed_errors = []
    
    while attempt < retries:
        try:
            # Record pre-request diagnostics
            pre_request_diag = {
                'attempt': attempt + 1,
                'timestamp': datetime.now().isoformat(),
                'system_state': get_system_diagnostics(),
                'connectivity_test': test_proxy_connectivity() if proxy_mode else None
            }
            
            start_time = time.time()
            response = requests.get(
                url, 
                proxies=proxies, 
                stream=True, 
                verify=False,
                timeout=(30, 300)  # connection timeout, read timeout
            )
            end_time = time.time()
            
            if response.status_code == 200:
                success_info = {
                    'attempt': attempt + 1,
                    'success': True,
                    'response_time': end_time - start_time,
                    'status_code': response.status_code,
                    'content_length': response.headers.get('content-length'),
                    'pre_request_diagnostics': pre_request_diag
                }
                detailed_errors.append(success_info)
                return response, detailed_errors
            else:
                error_info = {
                    'attempt': attempt + 1,
                    'success': False,
                    'status_code': response.status_code,
                    'response_time': end_time - start_time,
                    'headers': dict(response.headers),
                    'pre_request_diagnostics': pre_request_diag
                }
                detailed_errors.append(error_info)
                logger.warning(f"Failed to download data from {url}, status code: {response.status_code}")
                
        except requests.RequestException as e:
            end_time = time.time()
            error_info = {
                'attempt': attempt + 1,
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'response_time': end_time - start_time if 'start_time' in locals() else None,
                'traceback': traceback.format_exc(),
                'pre_request_diagnostics': pre_request_diag
            }
            detailed_errors.append(error_info)
            logger.warning(f"Error during download attempt {attempt + 1} for {url}: {e}")
            
        attempt += 1
        if attempt < retries:
            logger.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
    
    return None, detailed_errors

def collect_logs_into_zip(zipf):
    """Collect logs from /opt directories and add them to the zip file"""
    logger.info("Collecting logs from /opt directories...")
    special_logs = {
        "watchdog": "/opt/watchdog/watchdog_data/logs/watchdog.log",
        "threat-collector": "/opt/watchdog/elasticsearch_data/logs/threat_collector.log",
        "ucs-client": "/opt/watchdog/elasticsearch_data/logs/ucs_client.log"
    }
    
    for name, path in special_logs.items():
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors='ignore') as f:
                    zipf.writestr(f"opt_logs/{name}.log", f.read())
                logger.info(f"Added {name} log to ZIP from {path}")
            else:
                logger.warning(f"Log file not found: {path}")
                zipf.writestr(f"opt_logs/{name}_missing.txt", f"Log file not found at: {path}")
        except Exception as e:
            error_msg = f"Failed to read log {path}: {e}"
            zipf.writestr(f"opt_logs/{name}_error.txt", error_msg)
            logger.error(error_msg)

def create_final_zip_archive():
    """Create a single ZIP archive containing all capture sessions and opt logs"""
    start_time = capture_sessions[0]['timestamp'] if capture_sessions else datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    end_time = capture_sessions[-1]['timestamp'] if len(capture_sessions) > 1 else start_time
    
    zip_filename = f'network_capture_complete_{start_time}_to_{end_time}.zip'
    
    logger.info(f"Creating final ZIP archive: {zip_filename}")
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add all capture session files
        for i, session in enumerate(capture_sessions):
            session_label = session['label'] or f'session_{i+1}'
            session_folder = f"sessions/{session_label}_{session['timestamp']}"
            
            for temp_file in session['files']:
                if os.path.exists(temp_file):
                    arcname = os.path.basename(temp_file)
                    zipf.write(temp_file, f"{session_folder}/{arcname}")
                    logger.info(f"Added {temp_file} to ZIP as {session_folder}/{arcname}")
        
        # Add opt logs to zip (only once)
        collect_logs_into_zip(zipf)
        # Add troubleshoot script log
        if os.path.exists(SCRIPT_LOG_FILE):
            try:
                with open(SCRIPT_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    zipf.writestr("troubleshoot_logs/troubleshoot.log", f.read())
                logger.info("✅ Added troubleshoot.log to final ZIP.")
            except Exception as e:
                logger.error(f"❌ Failed to add troubleshoot.log to ZIP: {e}")
                zipf.writestr("troubleshoot_logs/error.txt", f"Error reading troubleshoot.log: {e}")

        
        # Add a comprehensive summary file
        summary = f"""Network Traffic Capture Complete Summary
===========================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Sessions: {len(capture_sessions)}
First Session: {start_time}
Last Session: {end_time}
Proxy Mode: {proxy_mode}
Proxy IP: {PROXY_IP}
Proxy Port: {PROXY_PORT}
TCPDUMP Available: {TCPDUMP_AVAILABLE}

Session Details:
"""
        for i, session in enumerate(capture_sessions):
            summary += f"\nSession {i+1}:\n"
            summary += f"  Timestamp: {session['timestamp']}\n"
            summary += f"  Label: {session['label'] or 'scheduled'}\n"
            summary += f"  Files: {len(session['files'])}\n"
            if 'diagnostics' in session:
                summary += f"  Had Connection Issues: {'Yes' if session['diagnostics'].get('had_errors') else 'No'}\n"
        
        zipf.writestr("complete_summary.txt", summary)
    
    logger.info(f"✅ Final ZIP archive created: {zip_filename}")
    return zip_filename

def cleanup_all_temp_files():
    """Remove all temporary files after final zipping"""
    for session in capture_sessions:
        for temp_file in session['files']:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    logger.info(f"Cleaned up temporary file: {temp_file}")
            except Exception as e:
                logger.error(f"Failed to cleanup {temp_file}: {e}")

# Global variables for single ZIP management
MAIN_ZIP_FILE = None
capture_sessions = []

def collect_data_with_capture(label=""):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    suffix = f"{label}_" if label else ""
    
    # Create temporary files in temp directory
    pcap_file = os.path.join(TEMP_DIR, f'{suffix}proxy_capture_{timestamp}.pcap')
    log_file = os.path.join(TEMP_DIR, f'{suffix}download_log_{timestamp}.txt')
    dumplog_file = os.path.join(TEMP_DIR, f'{suffix}tcpdump_log_{timestamp}.log')
    diagnostics_file = os.path.join(TEMP_DIR, f'{suffix}diagnostics_{timestamp}.json')
    
    temp_files = [pcap_file, log_file, dumplog_file, diagnostics_file]

    # Collect pre-session diagnostics
    session_diagnostics = {
        'session_start': datetime.now().isoformat(),
        'label': label,
        'scheduler_context': get_scheduler_context(),
        'pre_session_system': get_system_diagnostics(),
        'pre_session_connectivity': test_proxy_connectivity() if proxy_mode else None,
        'pre_session_processes': get_process_info(),
        'download_attempts': {},
        'had_errors': False,
        'tcpdump_available': TCPDUMP_AVAILABLE
    }

    tcpdump_proc = None
    if proxy_mode and TCPDUMP_AVAILABLE:
        logger.info(f"Starting tcpdump to {pcap_file}")
        logger.info(f"Monitoring traffic to proxy at {PROXY_IP}:{PROXY_PORT}")
        
        try:
            tcpdump_proc = subprocess.Popen(
                ['tcpdump', '-i', 'any', 'tcp', 'and', 'host', PROXY_IP, 'and', 'port', str(PROXY_PORT), '-w', pcap_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )

            # Start a thread to capture and log stderr output
            def log_tcpdump_stderr(pipe, logfile_path):
                with open(logfile_path, 'w') as log_file:
                    for line in iter(pipe.readline, ''):
                        logger.warning(f"[tcpdump] {line.strip()}")
                        log_file.write(line)
                    pipe.close()

            threading.Thread(target=log_tcpdump_stderr, args=(tcpdump_proc.stderr, dumplog_file), daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to start tcpdump: {e}")
            session_diagnostics['tcpdump_error'] = str(e)
    elif proxy_mode and not TCPDUMP_AVAILABLE:
        logger.warning("tcpdump not available - skipping packet capture")
        session_diagnostics['tcpdump_skipped'] = "tcpdump not available"
    else:
        logger.info("Proxy mode disabled - skipping tcpdump")

    try:
        time.sleep(2)  # Allow tcpdump to initialize

        with open(log_file, 'w') as log:
            log.write(f"Network Capture Session - {timestamp}\n")
            log.write(f"Label: {label or 'scheduled'}\n")
            log.write(f"Proxy: {PROXY_IP}:{PROXY_PORT}\n")
            log.write(f"TCPDUMP Available: {TCPDUMP_AVAILABLE}\n")
            log.write(f"Scheduler Context: {session_diagnostics['scheduler_context']}\n")
            log.write("="*50 + "\n\n")
            
            # PhishTank download with enhanced diagnostics
            log.write("Downloading from PhishTank...\n")
            try:
                r1, phish_errors = download_with_retry(PHISHTANK_URL)
                session_diagnostics['download_attempts']['phishtank'] = phish_errors
                
                if r1:
                    log.write(f"PhishTank status: {r1.status_code}, size: {len(r1.content)} bytes\n")
                else:
                    log.write("PhishTank failed after retries.\n")
                    session_diagnostics['had_errors'] = True
            except Exception as e:
                error_details = {
                    'error': str(e),
                    'traceback': traceback.format_exc(),
                    'timestamp': datetime.now().isoformat()
                }
                session_diagnostics['download_attempts']['phishtank'] = [error_details]
                session_diagnostics['had_errors'] = True
                log.write(f"PhishTank error: {e}\n")

            # URLHaus download with enhanced diagnostics  
            log.write("\nDownloading from URLHaus...\n")
            try:
                r2, urlhaus_errors = download_with_retry(URLHAUS_URL)
                session_diagnostics['download_attempts']['urlhaus'] = urlhaus_errors
                
                if r2:
                    log.write(f"URLHaus status: {r2.status_code}, size: {len(r2.content)} bytes\n")
                else:
                    log.write("URLHaus failed after retries.\n")
                    session_diagnostics['had_errors'] = True
            except Exception as e:
                error_details = {
                    'error': str(e),
                    'traceback': traceback.format_exc(),
                    'timestamp': datetime.now().isoformat()
                }
                session_diagnostics['download_attempts']['urlhaus'] = [error_details]
                session_diagnostics['had_errors'] = True
                log.write(f"URLHaus error: {e}\n")
                
            log.write(f"\nCapture completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Collect post-session diagnostics
        session_diagnostics.update({
            'session_end': datetime.now().isoformat(),
            'post_session_system': get_system_diagnostics(),
            'post_session_connectivity': test_proxy_connectivity() if proxy_mode else None,
            'post_session_processes': get_process_info()
        })

        # Save diagnostics to JSON file
        with open(diagnostics_file, 'w') as diag_file:
            json.dump(session_diagnostics, diag_file, indent=2, default=str)

    finally:
        if tcpdump_proc:
            logger.info("Stopping tcpdump...")
            tcpdump_proc.terminate()
            exit_code = tcpdump_proc.wait()
            logger.info(f"tcpdump terminated with exit code: {exit_code}")
            if exit_code != 0:
                logger.warning(f"tcpdump may have failed. Check logs at {dumplog_file}")
        
        # Store session info for later zipping
        session_info = {
            'timestamp': timestamp,
            'label': label,
            'files': temp_files.copy(),
            'diagnostics': session_diagnostics
        }
        capture_sessions.append(session_info)
        
        logger.info(f"✅ Session {len(capture_sessions)} completed: {timestamp}")
        if session_diagnostics['had_errors']:
            logger.warning(f"⚠️  Session had connection errors - check diagnostics file")
        
        if not label:
            logger.info("✅ Session completed, you can now stop script by pressing 'ctrl + c'")

def cleanup_temp_directory():
    """Clean up the temporary directory on exit"""
    try:
        if os.path.exists(TEMP_DIR):
            for file in os.listdir(TEMP_DIR):
                os.remove(os.path.join(TEMP_DIR, file))
            os.rmdir(TEMP_DIR)
            logger.info(f"Cleaned up temporary directory: {TEMP_DIR}")
    except Exception as e:
        logger.error(f"Failed to cleanup temporary directory: {e}")

if __name__ == '__main__':
    # Check system requirements before starting
    requirements_ok, tcpdump_ok = check_system_requirements()
    
    if not requirements_ok:
        print("\n❌ Critical requirements not met. Exiting.")
        exit(1)
    
    # Set global tcpdump availability
    TCPDUMP_AVAILABLE = tcpdump_ok
    
    try:
        print("\n" + "=" * 80)
        print("🛡️  Watchdog Network Diagnostics Script")
        print("=" * 80)
        print("This script will perform the following actions:")
        if TCPDUMP_AVAILABLE:
            print(" - Capture network traffic (pcap) to the proxy IP/port using tcpdump")
        else:
            print(" - ⚠️  Skip network packet capture (tcpdump not available)")
        print(" - Attempt downloads from PhishTank and URLHaus (via proxy if enabled)")
        print(" - Log detailed diagnostics (system info, proxy tests, process info, scheduler)")
        print(" - Store each session's diagnostics in JSON and a final ZIP")
        print(" - Collect logs from Watchdog and ETI components under /opt")
        print(" - Retry failed downloads up to 3 times with diagnostics")
        print(" - Create a ZIP archive with all sessions and logs upon interruption")
        print("=" * 80)
        print("📦 Temp directory used:", TEMP_DIR)
        print(f"🌐 Proxy Mode: {'Enabled' if proxy_mode else 'Disabled'}")
        print(f"📡 TCPDUMP Available: {'Yes' if TCPDUMP_AVAILABLE else 'No'}")
        print("[IMPORTANT] Once data is collected script will prompt you to press ctrl + c to stop execution, script will automatically then save all files to zip and do cleanup")
        if proxy_mode:
            print(f"🔌 Proxy IP: {PROXY_IP}, Port: {PROXY_PORT}")
        print("=" * 80)

        logger.info("🚀 Running initial test request (label: initial)...")
        collect_data_with_capture(label="initial")
        
        logger.info("⏱ Waiting 60 seconds before starting scheduled jobs...")
        time.sleep(60)

        scheduler = BlockingScheduler()
        scheduler.add_job(
            collect_data_with_capture,
            'interval',
            hours=6,
            next_run_time=datetime.now(),  # First scheduled call happens immediately
        )
        logger.info("🔁 Scheduler started. First run starting now...")
        scheduler.start()
        
    except KeyboardInterrupt:
        logger.info("Script interrupted by user - creating final ZIP...")
        if capture_sessions:
            zip_filename = create_final_zip_archive()
            cleanup_all_temp_files()
            cleanup_temp_directory()
            logger.info(f"🎯 All data saved in single ZIP: {zip_filename}")
        else:
            logger.info("No capture sessions to save")
    except Exception as e:
        logger.error(f"Script error: {e}")
        if capture_sessions:
            logger.info("Creating final ZIP before exit...")
            zip_filename = create_final_zip_archive()
            cleanup_all_temp_files()
            logger.info(f"🎯 All data saved in single ZIP: {zip_filename}")
    finally:
        cleanup_temp_directory()