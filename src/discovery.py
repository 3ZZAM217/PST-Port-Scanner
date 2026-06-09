import subprocess
import platform

def is_host_up(target: str) -> bool:
    """
    Checks if a host is up using the system's ping command.
    Returns True if the host responds, False otherwise.
    """
    # Determine the ping command based on OS
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', target]
    
    try:
        # Run ping command, suppressing output
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return output.returncode == 0
    except Exception:
        # If ping fails for some weird reason, assume it's up to avoid missing scans
        return True
