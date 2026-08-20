# Splunk example searches

These searches are lab-specific and assume endpoint file-event fields have been
normalized or mapped.

```spl
index=* (TargetFilename="*.SIMULATED_LOCKED" OR file_name="*.SIMULATED_LOCKED")
| stats count min(_time) as first_seen max(_time) as last_seen by host process_name
```

```spl
index=* (TargetFilename="*SIMULATED_RANSOM_NOTE.txt" OR file_name="SIMULATED_RANSOM_NOTE.txt")
| table _time host process_name TargetFilename file_name
```

Use the searches to validate telemetry and analyst workflow; they are not
universal ransomware detections.
