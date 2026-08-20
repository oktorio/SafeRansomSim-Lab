# Microsoft Sentinel / Defender example queries

These examples are intentionally keyed to **SafeRansomSim-Lab artifacts**.

```kusto
DeviceFileEvents
| where FileName endswith ".SIMULATED_LOCKED"
   or FileName == "SIMULATED_RANSOM_NOTE.txt"
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName, ActionType
| order by Timestamp asc
```

A simple burst view:

```kusto
DeviceFileEvents
| where FileName endswith ".SIMULATED_LOCKED"
| summarize SimulatedLockedFiles=count() by DeviceName, bin(Timestamp, 1m)
| where SimulatedLockedFiles > 1
```

Field availability depends on the telemetry source. Adapt only the field names
and time window; keep the exercise scoped to the disposable lab.
