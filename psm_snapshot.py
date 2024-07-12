import py7zr
import os
import json
import sys
import shutil
import requests
import logging
import urllib3
import paramiko
import hashlib
from datetime import datetime
from dotenv import load_dotenv
from datetime import datetime
from colorama import init, Fore, Style

# Disable HTTPS untrusted warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color definitions
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RED = Fore.RED
RESET = Style.RESET_ALL

# Load environment variables
load_dotenv()

# Logging and output configuration
log_enabled = os.getenv('LOG_ENABLED', 'False').lower() == 'true'
console_output_enabled = os.getenv('CONSOLE_OUTPUT_ENABLED', 'True').lower() == 'true'
log_path = os.getenv('LOG_PATH', '/var/log/pensando/snapshot')

if log_enabled:
    # Ensure the log directory exists
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Configure logging
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.getLogger('paramiko').setLevel(logging.WARN)
else:
    # Disable logging
    logging.getLogger().disabled = True

def print_blue(text):
    if console_output_enabled:
        print(Fore.BLUE + text + Style.RESET_ALL)

def print_green(text):
    if console_output_enabled:
        print(Fore.GREEN + text + Style.RESET_ALL)

def print_red(text):
    if console_output_enabled:
        print(Fore.RED + text + Style.RESET_ALL)

def print_yellow(text):
    if console_output_enabled:
        print(Fore.YELLOW + text + Style.RESET_ALL)

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Create custom logging and output functions
def log_info(message):
    timestamped_message = f"{get_timestamp()} - INFO: {message}"
    if log_enabled:
        logging.info(message)
    if console_output_enabled:
        print_blue(timestamped_message)

def log_error(message):
    timestamped_message = f"{get_timestamp()} - ERROR: {message}"
    if log_enabled:
        logging.error(message)
    if console_output_enabled:
        print_red(timestamped_message)

def log_success(message):
    timestamped_message = f"{get_timestamp()} - SUCCESS: {message}"
    if log_enabled:
        logging.info(message)
    if console_output_enabled:
        print_green(timestamped_message)

def log_warning(message):
    timestamped_message = f"{get_timestamp()} - WARNING: {message}"
    if log_enabled:
        logging.warning(message)
    if console_output_enabled:
        print_yellow(timestamped_message)

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Get credentials and API gateway URL from environment variables
username = os.getenv('USERNAME')
password = os.getenv('PASSWORD')
apigwurl = os.getenv('APIGWURL')
max_snapshots = int(os.getenv('MAX_SNAPSHOTS', 10))
zip_password = os.getenv('ZIP_PASSWORD')

# Parse destinations from environment variables
def parse_destinations(env_var):
    try:
        return json.loads(os.getenv(env_var, '[]'))
    except json.JSONDecodeError as e:
        log_error(f"Error parsing {env_var}: {str(e)}")
        return []

scp_destinations = parse_destinations('SCP_DESTINATIONS')
sftp_destinations = parse_destinations('SFTP_DESTINATIONS')
folder_destinations = parse_destinations('FOLDER_DESTINATIONS')

# Remove empty strings from lists
scp_destinations = list(filter(None, scp_destinations))
sftp_destinations = list(filter(None, sftp_destinations))
folder_destinations = list(filter(None, folder_destinations))

def handle_api_response(response, action_description):
    if response.status_code != 200:
        error_message = f"Failed to {action_description}. Status code: {response.status_code}"
        try:
            error_details = response.json()
            if 'message' in error_details:
                error_message += f"\nError: {error_details['message']}"
            elif 'error' in error_details:
                error_message += f"\nError: {error_details['error']}"
        except ValueError:
            error_message += f"\nResponse: {response.text}"
        
        log_error(error_message)
        return False
    return True

def parse_destination(dest_string):
    # Split the string at the last '@' to separate credentials from host info
    parts = dest_string.rsplit('@', 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid destination format: {dest_string}")
    
    cred_part, host_part = parts
    
    # Split host info
    host_parts = host_part.split(':')
    if len(host_parts) < 2:
        raise ValueError(f"Invalid destination format: {dest_string}")
    
    dest = {
        'host': host_parts[0],
        'port': 22,  # Default SSH port
        'path': host_parts[-1]  # The last part is always the path
    }
    
    if len(host_parts) > 2:
        dest['port'] = int(host_parts[1])
    
    # Handle credentials
    if ':' in cred_part:
        dest['username'], dest['password'] = cred_part.split(':', 1)
    else:
        dest['username'] = cred_part
        dest['password'] = None
    
    return dest

def compress_and_protect(file_path, password=None):
    if not file_path or not os.path.exists(file_path):
        log_error(f"File not found: {file_path}")
        return None
    
    output_path = file_path + '.7z'
    try:
        if password:
            with py7zr.SevenZipFile(output_path, 'w', password=password) as archive:
                archive.write(file_path, os.path.basename(file_path))
            log_info(f"File compressed and encrypted: {output_path}")
        else:
            with py7zr.SevenZipFile(output_path, 'w') as archive:
                archive.write(file_path, os.path.basename(file_path))
            log_info(f"File compressed without encryption: {output_path}")
        
        os.remove(file_path)  # Remove the original file
        return output_path
    except Exception as e:
        log_error(f"Error compressing file: {str(e)}")
        return None

def copy_to_folder(file_path, dest_folder):
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    shutil.copy2(file_path, os.path.join(dest_folder, os.path.basename(file_path)))

def upload_to_destinations(file_path, destinations):
    successful_uploads = 0
    hash_file_path = f"{file_path}.sha256"
    
    for dest in destinations:
        try:
            if dest['type'] in ['scp', 'sftp']:
                upload_ssh(file_path, dest)
                if os.path.exists(hash_file_path):
                    upload_ssh(hash_file_path, dest)
            elif dest['type'] == 'folder':
                copy_to_folder(file_path, dest['path'])
                if os.path.exists(hash_file_path):
                    copy_to_folder(hash_file_path, dest['path'])
            log_info(f"File uploaded to {dest['type']} destination: {dest.get('host', dest['path'])}")
            successful_uploads += 1
        except Exception as e:
            error_msg = f"Failed to upload to {dest['type']} destination: {dest.get('host', dest['path'])}. Error: {str(e)}"
            log_error(error_msg)
    
    log_success(f"Snapshot uploaded to {successful_uploads} out of {len(destinations)} destination(s)")
    
    # Remove the hash file after uploading
    if os.path.exists(hash_file_path):
        os.remove(hash_file_path)

def upload_ssh(file_path, dest):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            dest['host'],
            port=dest.get('port', 22),
            username=dest['username'],
            password=dest['password'],
            timeout=10
        )
        
        remote_path = os.path.join(dest['path'], os.path.basename(file_path))
        
        if dest['type'] == 'scp' or dest['type'] == 'sftp':
            with ssh.open_sftp() as sftp:
                sftp.put(file_path, remote_path)
    except paramiko.AuthenticationException:
        raise Exception("Authentication failed. Please check your username and password.")
    except paramiko.SSHException as ssh_exception:
        raise Exception(f"SSH error: {str(ssh_exception)}")
    except Exception as e:
        raise Exception(f"Error during {dest['type']} transfer: {str(e)}")
    finally:
        ssh.close()


log_info("Starting PSM snapshot creation and management...")
# Create a session object
s = requests.Session()
s.verify = False

# Login
login_url = f"{apigwurl}/v1/login"
login_headers = {'Content-Type': 'application/json'}
login_data = {
    "username": username,
    "password": password,
    "tenant": "default"
}
response = s.post(login_url, headers=login_headers, json=login_data, verify=False)
if not handle_api_response(response, "login"):
    sys.exit(1)

# Read PSM Cluster-Name
cluster_url = f"{apigwurl}/configs/cluster/v1/cluster"
response = s.get(cluster_url)
if not handle_api_response(response, "get cluster name"):
    sys.exit(1)
cluster_name = response.json().get('meta', {}).get('name')

# Create a snapshot
snapshot_url = f"{apigwurl}/configs/cluster/v1/config-snapshot/save"
snapshot_name = f"PSM-{cluster_name}-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}"
snapshot_data = {
    "meta": {
        "name": snapshot_name
    }
}
response = s.post(snapshot_url, json=snapshot_data)
if not handle_api_response(response, "create snapshot"):
    sys.exit(1)

# Check if the snapshot was created successfully
if response.status_code == 200:
    log_info(f"Snapshot {snapshot_name} created successfully")
else:
    log_error(f"Failed to create snapshot. Status code: {response.status_code}")
    sys.exit(1)

# Only proceed with download and copy if there are destinations
if scp_destinations or sftp_destinations or folder_destinations:
    # Get the snapshot details and download
    config_snapshot_url = f"{apigwurl}/configs/cluster/v1/config-snapshot"
    response = s.get(config_snapshot_url)
    if not handle_api_response(response, "get snapshot details"):
        sys.exit(1)

    if response.status_code == 200:
        snapshot_details = response.json()
        download_uri = snapshot_details['status']['last-snapshot']['uri']
        download_url = f"{apigwurl}{download_uri}"
        
        # Download the snapshot file
        snapshot_file_path = f"/tmp/{snapshot_name}.gz"
        with s.get(download_url, stream=True) as r:
            r.raise_for_status()
            with open(snapshot_file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192): 
                    f.write(chunk)
        
        log_info(f"Snapshot file downloaded to {snapshot_file_path}")

        # Process the snapshot file (compress and encrypt if needed)
        if zip_password:
            processed_file_path = compress_and_protect(snapshot_file_path, zip_password)
            log_success("\nSnapshot compressed and encrypted with password protection.")
        else:
            processed_file_path = snapshot_file_path
            log_info("Snapshot kept as is without encryption.")

        if not processed_file_path:
            log_error("Failed to process the snapshot file. Exiting.")
            sys.exit(1)

        calculate_hash = os.getenv('CALCULATE_HASH', 'False').lower() == 'true'
        if calculate_hash:
            file_hash = calculate_sha256(processed_file_path)
            hash_message = f"SHA-256 hash of {os.path.basename(processed_file_path)}: {file_hash}"
            log_info(hash_message)
            
            # Create a text file with the hash
            hash_file_path = f"{processed_file_path}.sha256"
            with open(hash_file_path, 'w') as f:
                f.write(hash_message)

        # Define destinations
        destinations = []
        for dest in scp_destinations:
            try:
                parsed = parse_destination(dest)
                parsed['type'] = 'scp'
                destinations.append(parsed)
                log_info(f"\nAdded SCP destination: {parsed['host']}:{parsed.get('port', 22)}")
            except ValueError as e:
                error_msg = f"Invalid SCP destination: {dest}. Error: {str(e)}"
                log_error(error_msg)

        for dest in sftp_destinations:
            try:
                parsed = parse_destination(dest)
                parsed['type'] = 'sftp'
                destinations.append(parsed)
                log_info(f"Added SFTP destination: {parsed['host']}:{parsed.get('port', 22)}")
            except ValueError as e:
                error_msg = f"Invalid SFTP destination: {dest}. Error: {str(e)}"
                log_error(error_msg)

        for dest in folder_destinations:
            destinations.append({'type': 'folder', 'path': dest})
            log_info(f"Added folder destination: {dest}")

        # Upload to all destinations
        upload_to_destinations(processed_file_path, destinations)

        # Remove local file
        os.remove(processed_file_path)
        hash_file_path = f"{processed_file_path}.sha256"
        if os.path.exists(hash_file_path):
            os.remove(hash_file_path)
        log_info(f"Local file {processed_file_path} and its hash file (if exists) removed")

    else:
        log_error(f"Failed to get snapshot details. Status code: {response.status_code}")
        sys.exit(1)
else:
    log_info("No destinations specified. Skipping download and copy.\n")

s.post(snapshot_url, json=snapshot_data)
response = s.post(snapshot_url, json=snapshot_data)
# Log the successful processing of cluster_name
log_success(f"\nSnapshot of {cluster_name} created successfully\n")


# Check number of snapshots and delete oldest if necessary
snapshots_url = f"{apigwurl}/objstore/v1/tenant/default/snapshots/objects"
response = s.get(snapshots_url)
if not handle_api_response(response, "get snapshots list"):
    sys.exit(1)
response = s.get(snapshots_url)
snapshots = response.json().get('items', [])  # Extract the list of snapshots

# Filter snapshots created by the script
snapshots = [snapshot for snapshot in snapshots if snapshot['meta']['name'].startswith('PSM-')]

# Sort snapshots by creation time
snapshots.sort(key=lambda x: x['meta']['creation-time'])

# Delete the n-oldest snapshots if the number exceeds the maximum retention
while len(snapshots) > max_snapshots:
    oldest_snapshot = snapshots.pop(0)
    delete_url = f"{apigwurl}/objstore/v1/tenant/default/snapshots/objects/{oldest_snapshot['meta']['name']}"
    response = s.delete(delete_url)
    if handle_api_response(response, f"delete snapshot {oldest_snapshot['meta']['name']}"):
        log_info(f"\nDeleted snapshot on PSM: {oldest_snapshot['meta']['name']}\n")
    else:
        log_error(f"Failed to delete snapshot: {oldest_snapshot['meta']['name']}")

# Log the names of the existing snapshots
for snapshot in snapshots:
    log_info(f"Remaining snapshot(s): {snapshot['meta']['name']}")