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
              || "misc",     # No platform or extension
    "platform":  "win32" 
              || "win64" 
              || "linux" 
              || "android",
              || "macos",
              || "freebsd",
              || "netbsd",
              || "openbsd",
              || "solaris",
    "extension": "*",        # Expected file extension
    "mime": "*",        # Expected file mimetype
    ... (other fields are derived from incoming task)
}
```

**Warning** the output `mime` field is not deterministic across libmagic versions and can change depending on the version you're using. We don't recommend creating consumers that listen on it directly.

## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton

Then install karton-classifier from PyPi:

```shell
$ pip install karton-classifier

$ karton-classifier
```


## YARA rule classifiers

Since karton-classifier v1.5.0 it's possible to extend the classifier logic using YARA rules.

You can enable it by passing `--yara-rules` with the path to the directory containing the rules. Each rule **has to** specify the resulting `kind` using the meta section. A working rule looks like this:

```yar
rule pe_file
{
    meta:
        description = "classifies incoming windows executables"
        kind = "runnable"
        platform = "win32"
        extension = "exe"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and uint32(uint32(0x3C)) == 0x4550
}
```

Some caveats to consider:
  * classifier will report samples classified by both the normal method and the YARA rules
  * if several YARA rules are matched classifier will report all of them (n matches == n outgoing tasks)
  * the outgoing task includes the matched rule name in `rule-name` in the task header


![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)
