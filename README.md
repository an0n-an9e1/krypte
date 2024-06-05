# Krypte
This project is an attempt of implementing the AES encryption algorithm. Currently it can only perform AES-128 encryption.
## Usage
This will encrypt the file plain.txt with the given 128bit key. And will create a file called `plain.txt.lock` where it will store the encrypted file.
```
krypte encrypt plain.txt -k "0348655456780009ffa6b1b37800eeaa"
```


If you want to encrypt a file without duplication, use the destructive method (note: here the original message will be lost, but can be recovered if decrypted:
```
krypte encrypt plain.txt -k "0348655456780009ffa6b1b37800eeaa" -d
```
```
krypte decrypt plain.txt -k "0348655456780009ffa6b1b37800eeaa" -d
```

This is the help screen provided by the `krypte -h`:
```
Usage: krypte encrypt <filename> -k <secret_key>
Modes:
	encrypt - used to encrypt files
	decrypt - used to decrypt files
Options:
	-v       - shows the version of the software
	-h       - prints this help screen
	-genkey  - used to create a default secret key for encryption/decryption without providing a key everytime
	-setkey  - used to set the default secret key for encryption/decryption without providing a key everytime
	-k <key> - used to provide a 128bit key for the current encryption/decryption of the file
	-d       - used to set the mode to destryctive meaning that the file provided will be erased and will be filled with the content of the encryption/decryption
```

## Installation
### Linux
To install on linux, first clone the repo and enter the directory. After that compile the program:
```
make
```
And with elevated privileges install:
```
make install
```

### Windows
For now there is no official support for Windows or Mac, but you can install it manually somehow :)
