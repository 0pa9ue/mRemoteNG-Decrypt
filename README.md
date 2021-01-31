# mRemoteNG-Decrypt

Reference : https://github.com/haseebT/mRemoteNG-Decrypt

This python script is used for decrypting mRemoteNG password and output the detailed information in csv format.

## Usages
``` 
usage: decrypt.py [-h] [-f FILEPATH | -s STRING] [-o OUTPUT] [-p PASSWORD]

optional arguments:
  -h, --help            show this help message and exit
  -f FILEPATH, --filepath FILEPATH
                        config file for mRemoteNG
  -s STRING, --string STRING
                        base64 string of mRemoteNG password
  -o OUTPUT, --output OUTPUT
                        output filename
  -p PASSWORD, --password PASSWORD
                        Custom password
```

## Run Script

``` 
python3 decrypt.py -f ./test/test.xml -o ./test/test.csv
```





