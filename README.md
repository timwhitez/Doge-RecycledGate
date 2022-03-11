# Doge-RecycledGate
Golang implementation of Hellsgate + Halosgate/Tartarosgate. Ensures that all systemcalls go through ntdll.dll; 

这只是 Hellsgate + Halosgate/Tartarusgate 的另一种实现。

但是，此实现确保所有系统调用仍通过 ntdll.dll来避免使用直接系统调用。

为此，我解析 ntdll 中未被挂钩的sysid 并重用现有syscall;ret指令——因此是该项目的名称。

这可能会绕过一些试图检测异常系统调用的 EDR。

示例程序可以在example文件夹中找到


This is just another implementation of Hellsgate + Halosgate/Tartarusgate.

However, this implementation makes sure that all system calls still go through ntdll.dll to avoid the usage of direct systemcalls. To do so, I parse the ntdll for nonhooked syscall-stubs and re-use existing syscall;ret instructions - thus the name of this project.

This probably bypasses some EDR trying to detect abnormal systemcalls.

The sample program can be found in the example folder

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

## 优化细节
相比原实现，

- 加入了随机选取syscall;ret
- 加入了自定义hash函数支持
- 加入了blacklist排除选项
- 加入了可选的指定syscall;ret api
- 优化了更加友好的调用方式
- 加入NOP混淆


## Reference
https://github.com/thefLink/RecycledGate

https://github.com/C-Sto/BananaPhone

https://golang.org/src/runtime/sys_windows_amd64.s

https://github.com/helpsystems/nanodump/blob/main/source/syscalls-asm.asm

https://github.com/am0nsec/HellsGate/ 


