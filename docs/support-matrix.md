# Support matrix

| Area | Current declaration |
| --- | --- |
| Operating environment | User-supplied Debian Live; exact image and persistence support must be checked per image |
| Architecture | Intended Debian Live / amd64 path; no exact image or PC combination verified yet |
| Nexus tools installer | Existing Nexus-owned `packaging/install.sh`; Boot does not replace it |
| Persistence | User-configured Debian Live persistence; Boot guidance only, no Boot-owned volume or lifecycle |
| OS image / removable-media writer | Not implemented or part of Boot scope; user prepares/writes their own SSD |
| Firmware / Secure Boot | Boot does not manage or attest host firmware |
| Separate-PC boot verification | In scope; pending a user-prepared SSD and designated PC |
| Authority | No Boot decision/enforcement authority; Azazel-Edge remains authoritative |

Future rows require a reviewed proposal and measured evidence. A package
installation test on a synthetic or disposable software environment is not a
hardware compatibility claim.
