# CC20
cc20 is a C implementation of the ChaCha20 algorithm. NOTE: This is not a secure or efficient implementation by any means and is only intended for education purpose.

## Compilation
```sh
gcc -o cc20 cc20.c ChaCha20.c fileIO.c md4.c
```

## Usage
```
cc20 <-e|d|h> [-i inputfile] [-o outputfile]
```

## Defaults
Option | Default | Description
--- | --- | --- |
`-i` | `-` | Reads input from stdin
`-o` | `-` | Print output to stdout

## Examples
```sh
cc20 -e -i plaintext -o ciphertext
cc20 -d -i ciphertext -o plaintext
```
