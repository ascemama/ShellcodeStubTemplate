#ShellCode Stub*ing* Templates

A template to manipulate/encrypt (X64) windows shellcode and play with EDR detection capabilities. Given a shellcode as input it return an "encrypted" shellcode which when will decrypt itself and run the original payload. Can be used as basis to implement more complex things.

1. Encryption is very basic: XOR with a random two bytes key, embedded in the returned shellcode.
2. The decryption stub is written in ASM and compiled during encryption. NASM must be installed.
3. encryption is done in Python and works as follow:
   1. generate a two bytes key
   2. XOR the shellcode with it
   3. compiled the ASM decryption stub with the correct shellcode length
   4. prepend the decryption stub to the XORed shellcode

` python.exe .\Encryptor.py -f .\shellcode.bin -o enc_shellcode.bin`

