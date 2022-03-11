package recycled

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"strings"

	_ "runtime/cgo"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"
)

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}


func GetCall(tarApi string,blacklist []string,hash func(string) string) uintptr {
	//init hasher
	hasher := func(a string)string{
		return a
	}
	if hash !=nil{
		hasher = hash
	}

	//tolower
	if blacklist != nil && tarApi == ""{
		for i,v := range blacklist{
			blacklist[i] = strings.ToLower(v)
		}
	}


	Ntd, _, _ := gMLO(1)
	if Ntd == 0 {
		return 0
	}

	fmt.Printf("NtdllBaseAddr: 0x%x\n", Ntd)

	addrMod := Ntd

	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return 0
	}
	//windows.SleepEx(50, false)
	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return 0
	}

	rr := rawreader.New(addrMod, int(modSize))
	p, e := pe.NewFileFromMemory(rr)
	if e != nil {
		return 0
	}
	ex, e := p.Exports()

	rand.Seed(time.Now().UnixNano())
	for i := range ex {
		j := rand.Intn(i + 1)
		ex[i], ex[j] = ex[j], ex[i]
	}

	for i := 0; i < len(ex); i++ {
		exp := ex[i]
		if tarApi != ""{
			if strings.ToLower(hasher(exp.Name)) == strings.ToLower(tarApi)||strings.ToLower(hasher(strings.ToLower(exp.Name))) == strings.ToLower(tarApi) {
				fmt.Println("Syscall API: " + exp.Name)
				offset := rvaToOffset(p, exp.VirtualAddress)
				b, e := p.Bytes()
				if e != nil {
					return 0
				}
				buff := b[offset : offset+32]
				if buff[18] == 0x0f && buff[19] == 0x05 && buff[20] == 0xc3 {
					fmt.Printf("Syscall;ret Address: 0x%x\n", Ntd+uintptr(exp.VirtualAddress)+uintptr(18))
					return Ntd + uintptr(exp.VirtualAddress) + uintptr(18)
				}
			}
		}else {
			if strings.HasPrefix(exp.Name, "Nt") || strings.HasPrefix(exp.Name, "Zw"){
					if !contains(blacklist, strings.ToLower(hasher(exp.Name))) && !contains(blacklist, strings.ToLower(hasher(strings.ToLower(exp.Name)))) {
					fmt.Println("Syscall API: " + exp.Name)
					offset := rvaToOffset(p, exp.VirtualAddress)
					b, e := p.Bytes()
					if e != nil {
						return 0
					}
					buff := b[offset : offset+32]
					if buff[18] == 0x0f && buff[19] == 0x05 && buff[20] == 0xc3 {
						fmt.Printf("Syscall;ret Address: 0x%x\n", Ntd+uintptr(exp.VirtualAddress)+uintptr(18))
						return Ntd + uintptr(exp.VirtualAddress) + uintptr(18)
					}
				}
			}
		}
	}
	return 0
}

//GetModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func gMLO(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *sstring
	start, size, badstring = getMLO(i)
	modulepath = badstring.String()
	return
}

//NtdllHgate takes the exported syscall name and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func DiskHgate(funcname string, hash func(string) string) (uint16, error) {
	return getSysIDFromDisk(funcname, hash)
}

//NtdllHgate takes the exported syscall name and gets the ID it refers to. This function will access the ntdll file _on disk_, and relevant events/logs will be generated for those actions.
func MemHgate(funcname string, hash func(string) string) (uint16, error) {
	return getSysIDFromMem(funcname, hash)
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromMem(funcname string, hash func(string) string) (uint16, error) {
	//Get dll module BaseAddr
	//get ntdll handler
	Ntd, _, _ := gMLO(1)
	if Ntd == 0 {
		return 0, fmt.Errorf("err GetModuleHandleA")
	}
	//moduleInfo := windows.ModuleInfo{}
	//err := windows.GetModuleInformation(windows.Handle(uintptr(0xffffffffffffffff)), windows.Handle(Ntd), &moduleInfo, uint32(unsafe.Sizeof(moduleInfo)))

	//if err != nil {
	//	return 0, err
	//}
	//addrMod := moduleInfo.BaseOfDll
	addrMod := Ntd

	//get ntheader of ntdll
	ntHeader := ntH(addrMod)
	if ntHeader == nil {
		return 0, fmt.Errorf("get ntHeader err")
	}
	windows.SleepEx(50, false)
	//get module size of ntdll
	modSize := ntHeader.OptionalHeader.SizeOfImage
	if modSize == 0 {
		return 0, fmt.Errorf("get module size err")
	}
	//fmt.Println("ntdll module size: " + strconv.Itoa(int(modSize)))

	rr := rawreader.New(addrMod, int(modSize))
	p, e := pe.NewFileFromMemory(rr)

	if e != nil {
		return 0, e
	}
	ex, e := p.Exports()
	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcname) {
			offset := rvaToOffset(p, exp.VirtualAddress)
			b, e := p.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			// First opcodes should be :
			//    MOV R10, RCX
			//    MOV RAX, <syscall>
			if buff[0] == 0x4c &&
				buff[1] == 0x8b &&
				buff[2] == 0xd1 &&
				buff[3] == 0xb8 &&
				buff[6] == 0x00 &&
				buff[7] == 0x00 {
				return sysIDFromRawBytes(buff)
			} else {
				for idx := uintptr(1); idx <= 500; idx++ {
					// check neighboring syscall down
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) + idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) + idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) + idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) + idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) + idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) + idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) + idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) + idx*IDX))
						return Uint16Down(buff[4:8], uint16(idx)), nil
					}

					// check neighboring syscall up
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) - idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) - idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) - idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) - idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) - idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) - idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) - idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) - idx*IDX))
						return Uint16Up(buff[4:8], uint16(idx)), nil
					}
				}
			}

			return 0, errors.New("Could not find sID")
		}
	}
	return 0, errors.New("Could not find sID")
}

//getSysIDFromMemory takes values to resolve, and resolves from disk.
func getSysIDFromDisk(funcname string, hash func(string) string) (uint16, error) {
	l := string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})
	p, e := pe.Open(l)
	if e != nil {
		return 0, e
	}
	ex, e := p.Exports()
	for _, exp := range ex {
		if strings.ToLower(hash(exp.Name)) == strings.ToLower(funcname) || strings.ToLower(hash(strings.ToLower(exp.Name))) == strings.ToLower(funcname) {
			offset := rvaToOffset(p, exp.VirtualAddress)
			b, e := p.Bytes()
			if e != nil {
				return 0, e
			}
			buff := b[offset : offset+10]

			// First opcodes should be :
			//    MOV R10, RCX
			//    MOV RAX, <syscall>
			if buff[0] == 0x4c &&
				buff[1] == 0x8b &&
				buff[2] == 0xd1 &&
				buff[3] == 0xb8 &&
				buff[6] == 0x00 &&
				buff[7] == 0x00 {
				return sysIDFromRawBytes(buff)
			} else {
				for idx := uintptr(1); idx <= 500; idx++ {
					// check neighboring syscall down
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) + idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) + idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) + idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) + idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) + idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) + idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) + idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) + idx*IDX))
						return Uint16Down(buff[4:8], uint16(idx)), nil
					}

					// check neighboring syscall up
					if *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[0])) - idx*IDX)) == 0x4c &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[1])) - idx*IDX)) == 0x8b &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[2])) - idx*IDX)) == 0xd1 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[3])) - idx*IDX)) == 0xb8 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[6])) - idx*IDX)) == 0x00 &&
						*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[7])) - idx*IDX)) == 0x00 {
						buff[4] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[4])) - idx*IDX))
						buff[5] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&buff[5])) - idx*IDX))
						return Uint16Up(buff[4:8], uint16(idx)), nil
					}
				}
			}
			return 0, errors.New("Could not find sID")
		}
	}
	return 0, errors.New("Could not find sID")
}

//rvaToOffset converts an RVA value from a PE file into the file offset. When using binject/debug, this should work fine even with in-memory files.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

//sysIDFromRawBytes takes a byte slice and determines if there is a sysID in the expected location. Returns a MayBeHookedError if the signature does not match.
func sysIDFromRawBytes(b []byte) (uint16, error) {
	return binary.LittleEndian.Uint16(b[4:8]), nil
}

func Uint16Down(b []byte, idx uint16) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) - idx | uint16(b[1])<<8
}
func Uint16Up(b []byte, idx uint16) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) + idx | uint16(b[1])<<8
}

//HgSyscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func HgSyscall(callid uint16, syscallA uintptr, argh ...uintptr) (errcode uint32, err error) {

	errcode = hgSyscall(callid, syscallA, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func ntH(baseAddress uintptr) *IMAGE_NT_HEADERS {
	return (*IMAGE_NT_HEADERS)(unsafe.Pointer(baseAddress + uintptr((*IMAGE_DOS_HEADER)(unsafe.Pointer(baseAddress)).E_lfanew)))
}

//sstring is the stupid internal windows definiton of a unicode string. I hate it.
type sstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s sstring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}

//Syscall calls the system function specified by callid with n arguments. Works much the same as syscall.Syscall - return value is the call error code and optional error text. All args are uintptrs to make it easy.
func hgSyscall(callid uint16, syscallA uintptr, argh ...uintptr) (errcode uint32)

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getMLO(i int) (start uintptr, size uintptr, modulepath *sstring)
