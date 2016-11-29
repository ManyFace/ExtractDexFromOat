# ExtractDexFromOat
Since Android L, DEX files in an APK will be transformed into OAT file when installed. An OAT file is actually ELF file whose <br>
type is shared object. This tool first parses the OAT file and then stores the DEX files that are inside of the OAT file.

##Dependency
python2.7 <br>

##Platform
Tested on Ubuntu and Windows<br>

##Usage
Run the following command:<br>
```Bash
python main.py -f oat_file_path [-v {L,M,N}] [--fix-checksum]
```
* oat_file_path: The path of oat file.
* L, M, N: L means AndroidL, M means AndroidM and N means AndroidN. Default is L.
* --fix-checksum: Fix the checksum of output dex files if you use this parameter.

Example:<br>
```Bash
python main.py -f extra/demo.oat -v L --fix-checksum
```

The extracted dex files will be saved to "out" folder which is located in current work directory.

##Note
* Only tested for AndroidL, AndroidM and AndroidN(32bit)
