# ExtractDexFromOat
Since Android L, dex in apk will be transformed to oat file when installed. Oat file is actually elf file whose <br>
type is shared object. This tool first parses oat file and then stores the dex files embedded in oat file.

##Dependency
python2.7 <br>

##Platform
Tested on unbuntu and windows<br>

##Usage
Run the following command:<br>
```Bash
python main.py -f <oat_file_path>
```
Example:<br>
```Bash
python main.py -f extra/demo.oat
```

The extracted dex files will be saved to "out" folder which is located in current work directory.

##Note
* This tool works for oat file which is produced by Android 5.1.1 (32bit) and didn't test other android versions.
