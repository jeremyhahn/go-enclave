package armtrustzone

import "unsafe"

// The Linux TEE subsystem's user-space ABI, as include/uapi/linux/tee.h
// defines it at the kernel the fixture pins (docs/reference/linux-uapi-tee.h).
// Every struct here has the header's layout on linux/arm64 and linux/amd64;
// tee_linux_test.go checks the sizes and the field offsets.

// The ioctl type and the first command number (TEE_IOC_MAGIC, TEE_IOC_BASE).
const (
	teeIOCMagic = 0xa4
	teeIOCBase  = 0
)

// Generic capabilities TEE_IOC_VERSION reports (TEE_GEN_CAP_*).
const (
	teeGenCapGP     = 1 << 0 // a GlobalPlatform-compliant TEE
	teeGenCapRegMem = 1 << 2 // registering user memory as shared memory
)

// Parameter types (TEE_IOCTL_PARAM_ATTR_TYPE_*), the TEEC_Operation
// parameter types of the GP TEE Client API.
const (
	teeParamAttrTypeNone         = 0
	teeParamAttrTypeValueOutput  = 2
	teeParamAttrTypeMemrefOutput = 6
)

// teeIOCtlLoginPublic is TEEC_LOGIN_PUBLIC (TEE_IOCTL_LOGIN_PUBLIC).
const teeIOCtlLoginPublic = 0

// teeIOCtlUUIDLen is TEE_IOCTL_UUID_LEN.
const teeIOCtlUUIDLen = 16

// teeNumParams is how many parameters every call carries: a TEEC_Operation
// has four, and the unused ones are TEE_IOCTL_PARAM_ATTR_TYPE_NONE.
const teeNumParams = 4

// teeVersionData is struct tee_ioctl_version_data.
type teeVersionData struct {
	ImplID   uint32
	ImplCaps uint32
	GenCaps  uint32
}

// teeShmAllocData is struct tee_ioctl_shm_alloc_data.
type teeShmAllocData struct {
	Size  uint64
	Flags uint32
	ID    int32
}

// teeBufData is struct tee_ioctl_buf_data.
type teeBufData struct {
	BufPtr uint64
	BufLen uint64
}

// teeParam is struct tee_ioctl_param. For a memref A is the offset into the
// shared memory, B its size and C the shared memory's id; for a value A and B
// are the value.
type teeParam struct {
	Attr uint64
	A    uint64
	B    uint64
	C    uint64
}

// teeOpenSessionArg is struct tee_ioctl_open_session_arg, without its
// flexible params array.
type teeOpenSessionArg struct {
	UUID      [teeIOCtlUUIDLen]byte
	ClntUUID  [teeIOCtlUUIDLen]byte
	ClntLogin uint32
	CancelID  uint32
	Session   uint32
	Ret       uint32
	RetOrigin uint32
	NumParams uint32
}

// teeOpenSessionBuf is the buffer TEE_IOC_OPEN_SESSION reads: the argument
// followed by its params.
type teeOpenSessionBuf struct {
	Arg    teeOpenSessionArg
	Params [teeNumParams]teeParam
}

// teeInvokeArg is struct tee_ioctl_invoke_arg, without its flexible params
// array.
type teeInvokeArg struct {
	Func      uint32
	Session   uint32
	CancelID  uint32
	Ret       uint32
	RetOrigin uint32
	NumParams uint32
}

// teeInvokeBuf is the buffer TEE_IOC_INVOKE reads: the argument followed by
// its params.
type teeInvokeBuf struct {
	Arg    teeInvokeArg
	Params [teeNumParams]teeParam
}

// teeCancelArg is struct tee_ioctl_cancel_arg.
type teeCancelArg struct {
	CancelID uint32
	Session  uint32
}

// teeCloseSessionArg is struct tee_ioctl_close_session_arg.
type teeCloseSessionArg struct {
	Session uint32
}

// teeShmRegisterData is struct tee_ioctl_shm_register_data.
type teeShmRegisterData struct {
	Addr   uint64
	Length uint64
	Flags  uint32
	ID     int32
}

// The asm-generic ioctl encoding (include/uapi/asm-generic/ioctl.h), which
// arm64 and amd64 both use: direction, size, type, number.
const (
	iocNRShift   = 0
	iocTypeShift = 8
	iocSizeShift = 16
	iocDirShift  = 30

	iocWrite = 1
	iocRead  = 2
)

// The TEE ioctl numbers (TEE_IOC_*), each _IOR or _IOWR over its argument.
const (
	teeIOCVersion      = iocRead<<iocDirShift | unsafe.Sizeof(teeVersionData{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+0)<<iocNRShift
	teeIOCShmAlloc     = (iocRead|iocWrite)<<iocDirShift | unsafe.Sizeof(teeShmAllocData{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+1)<<iocNRShift
	teeIOCOpenSession  = iocRead<<iocDirShift | unsafe.Sizeof(teeBufData{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+2)<<iocNRShift
	teeIOCInvoke       = iocRead<<iocDirShift | unsafe.Sizeof(teeBufData{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+3)<<iocNRShift
	teeIOCCancel       = iocRead<<iocDirShift | unsafe.Sizeof(teeCancelArg{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+4)<<iocNRShift
	teeIOCCloseSession = iocRead<<iocDirShift | unsafe.Sizeof(teeCloseSessionArg{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+5)<<iocNRShift
	teeIOCShmRegister  = (iocRead|iocWrite)<<iocDirShift | unsafe.Sizeof(teeShmRegisterData{})<<iocSizeShift | teeIOCMagic<<iocTypeShift | (teeIOCBase+9)<<iocNRShift
)
