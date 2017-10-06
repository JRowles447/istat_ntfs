# istat_ntfs
----
Imitates Brian Carriers implementation of istat. A specified version that operates on disk images utilizing ntfs file system. More information about Brian Carrier's open source digital forensic tools: https://www.sleuthkit.org/

## Running istat_ntfs
---
Run from root of the project directory with:
`python istat_ntfs.py image.ntfs 1`

istat_ntfs.py takes two positional arguments:
+ image: Path to NTFS raw image (in this example, "image.ntfs")
+ address: Metda-data number to display stats on (in this example, "1")

istat_ntfs.py also takes optional arguments:
+ -h --help: Provides information about istat_ntfs
+ -o imgoffset: Offset of the files system in the image (in sectors)
+ -b dev_sector_size: Size (in bytes) of the device sectors

## Dependencies
---
Uses Python version 3.5.3

## Sample Output
---
```
> python istat_ntfs.py image.ntfs 1
MFT Entry Header Values:
Entry: 1        Sequence: 1
$LogFile Sequence Number: 0
Allocated File
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Hidden, System
Owner ID: 0
Created:        2017-04-07 19:04:24.000 (EDT)
File Modified:  2017-04-07 19:04:24.000 (EDT)
MFT Modified:   2017-04-07 19:04:24.000 (EDT)
Accessed:       2017-04-07 19:04:24.000 (EDT)

$FILE_NAME Attribute Values:
Flags: Hidden, System
Name: $MFTMirr
Parent MFT Entry: 5     Sequence: 5
Allocated Size: 4096    Actual Size: 4096
Created:        2017-04-07 19:04:24.000 (EDT)
File Modified:  2017-04-07 19:04:24.000 (EDT)
MFT Modified:   2017-04-07 19:04:24.000 (EDT)
Accessed:       2017-04-07 19:04:24.000 (EDT)

Attributes:
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 82
Type: $DATA (128-1)   Name: N/A   Non-Resident   size: 4096  init_size: 4096
5004 5005 5006 5007
```
