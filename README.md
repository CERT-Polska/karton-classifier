# Classifier karton service

File type classifier for the Karton framework.

Entrypoint for samples. Classifies type of samples labeled as `kind: raw`,
which makes them available for subsystems that receive samples with specific
type only (e.g. `raw` => `runnable:win32:exe`)

**Author**: CERT.pl

**Maintainers**: psrok1, msm, nazywam

**Consumes:**
```
{
    "type": "sample",
    "kind": "raw"
    "payload": {
        "magic":  "output from 'file' command",
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
              || "archive"   # Archive containing samples (zip, e-mails)
              || "dump"      # Dump from sandbox
              || "script",   # Script (js/vbs/bat...)
    "platform":  "win32" 
              || "win64" 
              || "linux" 
              || "android",
              || "macos",
    "extension": "*",        # Expected file extension
    ... (other fields are derived from incoming task)
}
```

## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton

Then install karton-classifier from PyPi:

```shell
$ pip install karton-classifier

$ karton-classifier
```

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
