# Classifier karton service

Performs initial classification of sample type. Default karton entrypoint for unrecognized samples.

Author: CERT.pl

**Consumes:**
```
{
    "type": "sample",
    "kind": "raw"
    "payload": {
        "magic":  "output from 'file' command", # optional
        "sample": <Resource>
    }
} 
```

**Produces:**
```
{
    "type":      "sample",
    "stage":     "recognized",
    "kind":      "runnable"  # Executable format default for OS platform
              || "document"  # Office document
              || "archive"   # Archives containing samples (zip, e-mails)
              || "dump"      # Dumps from sandbox
              || "script",   # Scripts (js/vbs/bat...)
    "platform":  "win32" || "win64" || "linux" || "android",
    "extension": "*",        # Expected file extension
    ... (consumed task is derived)
}
```
