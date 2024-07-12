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
#Logging configuration<br />
LOG_ENABLED=True<br />
LOG_PATH=/var/log/pensando/snapshot<br />
CONSOLE_OUTPUT_ENABLED=True<br />

#Hash Calculation<br />
CALCULATE_HASH=True<br />

#PSM Credentials<br />
USERNAME=<user><br />
PASSWORD=<password><br />
APIGWURL=https://<psm_host><br />

#Snapshot Retention<br />
MAX_SNAPSHOTS=10<br />

#Define Destinations<br />
SCP_DESTINATIONS=\*["<user>:<password>@<host>:<port>:/<folder>"]\*<br />
SFTP_DESTINATIONS=["<user>:<password>@<host>:<port>:/<folder>"]<br />
FOLDER_DESTINATIONS=["/mnt/folder1", "/mnt/folder2"]<br />

#Password for zipfile protection<br />
ZIP_PASSWORD=<password><br />
```
