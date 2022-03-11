# Doge-RecycledGate
Golang implementation of Hellsgate + Halosgate/Tartarosgate. Ensures that all systemcalls go through ntdll.dll; 


## Usage
```
//NtDelayExecution HellsGate
	sleep1, e := recycled.MemHgate("84804f99e2c7ab8aee611d256a085cf4879c4be8", str2sha1)
	if e != nil {
		panic(e)
	}

	//callAddr := recycled.GetCall("",nil,nil)
	callAddr := recycled.GetCall("NtDelayExecution",nil,nil)
  //callAddr := recycled.GetCall("",apiblacklist,str2sha1)

	r, e1 := recycled.HgSyscall(sleep1, callAddr, 0, uintptr(unsafe.Pointer(&times)))
  if e1 != nil{
    fmt.Println(r)
	  fmt.Println(e1)
  }
```
