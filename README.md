# PSM Snapshot Tool

The PSM Snapshot Tool helps you to create snaphots for PSM

## Features

- Create PSM snapshots
- Encrypt snapshots with password protection (optional)
- Distribute snapshots to multiple destinations (optional):
  - SCP
  - SFTP
  - Mounted folders

![](https://github.com/Max1211/Images/blob/main/psm_snapshot.png)


### Example .env file:
```
#Logging configuration
LOG_ENABLED=True
LOG_PATH=/var/log/pensando/snapshot
CONSOLE_OUTPUT_ENABLED=True

#Hash Calculation
CALCULATE_HASH=True

#PSM Credentials
USERNAME=<user>
PASSWORD=<password>
APIGWURL=https://<psm_host>

#Snapshot Retention
MAX_SNAPSHOTS=10

#Define Destinations
SCP_DESTINATIONS=["<user>:<password>@<host>:<port>:/<folder>"]
SFTP_DESTINATIONS=["<user>:<password>@<host>:<port>:/<folder>"]
FOLDER_DESTINATIONS=["/mnt/folder1", "/mnt/folder2"]

#Password for zipfile protection
ZIP_PASSWORD=<password>
```
