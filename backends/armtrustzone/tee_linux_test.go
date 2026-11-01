package armtrustzone

import (
	"testing"
	"unsafe"
)

// The expected sizes, offsets and numbers are read off
// docs/reference/linux-uapi-tee.h, the header at the kernel the fixture pins.

func TestABIStructLayout(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"sizeof(tee_ioctl_version_data)", unsafe.Sizeof(teeVersionData{}), 12},
		{"tee_ioctl_version_data.impl_caps", unsafe.Offsetof(teeVersionData{}.ImplCaps), 4},
		{"tee_ioctl_version_data.gen_caps", unsafe.Offsetof(teeVersionData{}.GenCaps), 8},

		{"sizeof(tee_ioctl_shm_alloc_data)", unsafe.Sizeof(teeShmAllocData{}), 16},
		{"tee_ioctl_shm_alloc_data.flags", unsafe.Offsetof(teeShmAllocData{}.Flags), 8},
		{"tee_ioctl_shm_alloc_data.id", unsafe.Offsetof(teeShmAllocData{}.ID), 12},

		{"sizeof(tee_ioctl_buf_data)", unsafe.Sizeof(teeBufData{}), 16},
		{"tee_ioctl_buf_data.buf_len", unsafe.Offsetof(teeBufData{}.BufLen), 8},

		{"sizeof(tee_ioctl_param)", unsafe.Sizeof(teeParam{}), 32},
		{"tee_ioctl_param.a", unsafe.Offsetof(teeParam{}.A), 8},
		{"tee_ioctl_param.b", unsafe.Offsetof(teeParam{}.B), 16},
		{"tee_ioctl_param.c", unsafe.Offsetof(teeParam{}.C), 24},

		{"sizeof(tee_ioctl_open_session_arg)", unsafe.Sizeof(teeOpenSessionArg{}), 56},
		{"tee_ioctl_open_session_arg.clnt_uuid", unsafe.Offsetof(teeOpenSessionArg{}.ClntUUID), 16},
		{"tee_ioctl_open_session_arg.clnt_login", unsafe.Offsetof(teeOpenSessionArg{}.ClntLogin), 32},
		{"tee_ioctl_open_session_arg.cancel_id", unsafe.Offsetof(teeOpenSessionArg{}.CancelID), 36},
		{"tee_ioctl_open_session_arg.session", unsafe.Offsetof(teeOpenSessionArg{}.Session), 40},
		{"tee_ioctl_open_session_arg.ret", unsafe.Offsetof(teeOpenSessionArg{}.Ret), 44},
		{"tee_ioctl_open_session_arg.ret_origin", unsafe.Offsetof(teeOpenSessionArg{}.RetOrigin), 48},
		{"tee_ioctl_open_session_arg.num_params", unsafe.Offsetof(teeOpenSessionArg{}.NumParams), 52},
		{"tee_ioctl_open_session_arg.params", unsafe.Offsetof(teeOpenSessionBuf{}.Params), 56},
		{"sizeof(open session buffer)", unsafe.Sizeof(teeOpenSessionBuf{}), 56 + teeNumParams*32},

		{"sizeof(tee_ioctl_invoke_arg)", unsafe.Sizeof(teeInvokeArg{}), 24},
		{"tee_ioctl_invoke_arg.session", unsafe.Offsetof(teeInvokeArg{}.Session), 4},
		{"tee_ioctl_invoke_arg.cancel_id", unsafe.Offsetof(teeInvokeArg{}.CancelID), 8},
		{"tee_ioctl_invoke_arg.ret", unsafe.Offsetof(teeInvokeArg{}.Ret), 12},
		{"tee_ioctl_invoke_arg.ret_origin", unsafe.Offsetof(teeInvokeArg{}.RetOrigin), 16},
		{"tee_ioctl_invoke_arg.num_params", unsafe.Offsetof(teeInvokeArg{}.NumParams), 20},
		{"tee_ioctl_invoke_arg.params", unsafe.Offsetof(teeInvokeBuf{}.Params), 24},
		{"sizeof(invoke buffer)", unsafe.Sizeof(teeInvokeBuf{}), 24 + teeNumParams*32},

		{"sizeof(tee_ioctl_cancel_arg)", unsafe.Sizeof(teeCancelArg{}), 8},
		{"tee_ioctl_cancel_arg.session", unsafe.Offsetof(teeCancelArg{}.Session), 4},

		{"sizeof(tee_ioctl_close_session_arg)", unsafe.Sizeof(teeCloseSessionArg{}), 4},

		{"sizeof(tee_ioctl_shm_register_data)", unsafe.Sizeof(teeShmRegisterData{}), 24},
		{"tee_ioctl_shm_register_data.length", unsafe.Offsetof(teeShmRegisterData{}.Length), 8},
		{"tee_ioctl_shm_register_data.flags", unsafe.Offsetof(teeShmRegisterData{}.Flags), 16},
		{"tee_ioctl_shm_register_data.id", unsafe.Offsetof(teeShmRegisterData{}.ID), 20},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestABIIoctlNumbers(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"TEE_IOC_VERSION", teeIOCVersion, 0x800ca400},
		{"TEE_IOC_SHM_ALLOC", teeIOCShmAlloc, 0xc010a401},
		{"TEE_IOC_OPEN_SESSION", teeIOCOpenSession, 0x8010a402},
		{"TEE_IOC_INVOKE", teeIOCInvoke, 0x8010a403},
		{"TEE_IOC_CANCEL", teeIOCCancel, 0x8008a404},
		{"TEE_IOC_CLOSE_SESSION", teeIOCCloseSession, 0x8004a405},
		{"TEE_IOC_SHM_REGISTER", teeIOCShmRegister, 0xc018a409},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

func TestABIConstants(t *testing.T) {
	cases := []struct {
		name      string
		got, want uint64
	}{
		{"TEE_IOC_MAGIC", teeIOCMagic, 0xa4},
		{"TEE_GEN_CAP_GP", teeGenCapGP, 1},
		{"TEE_GEN_CAP_REG_MEM", teeGenCapRegMem, 4},
		{"TEE_IOCTL_PARAM_ATTR_TYPE_NONE", teeParamAttrTypeNone, 0},
		{"TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT", teeParamAttrTypeValueOutput, 2},
		{"TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT", teeParamAttrTypeMemrefOutput, 6},
		{"TEE_IOCTL_LOGIN_PUBLIC", teeIOCtlLoginPublic, 0},
		{"TEE_IOCTL_UUID_LEN", teeIOCtlUUIDLen, uuidLen},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
