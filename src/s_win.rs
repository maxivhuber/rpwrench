use windows::core::HRESULT;

#[inline]
fn win32_err_string(err: HRESULT) -> String {
    err.message().to_string_lossy()
}

pub mod memory {
    use std::ffi::c_void;

    use windows::Win32::{
        Foundation::HANDLE,
        System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    };

    #[inline]
    pub fn read_process_memory<T>(
        hprocess: HANDLE,
        lpbaseaddress: usize,
        lpbuffer: &mut [T],
        nsize: usize,
        lpnumberofbytesread: &mut usize,
    ) -> bool {
        assert_eq!(lpbuffer.len(), nsize);

        let lpbaseaddress = (lpbaseaddress as *const usize).cast::<c_void>();
        let lpbuffer = lpbuffer.as_mut_ptr().cast::<c_void>();

        unsafe {
            ReadProcessMemory(
                hprocess,
                lpbaseaddress,
                lpbuffer,
                nsize,
                lpnumberofbytesread,
            )
            .as_bool()
        }
    }

    pub fn write_process_memory<T>(
        hprocess: HANDLE,
        lpbaseaddress: usize,
        lpbuffer: &mut [T],
        nsize: usize,
        lpnumberofbyteswritten: &mut usize,
    ) -> bool {
        assert!(lpbuffer.len() <= nsize);

        let lpbaseaddress = (lpbaseaddress as *const usize).cast::<c_void>();
        let lpbuffer = lpbuffer.as_ptr().cast::<c_void>();

        unsafe {
            WriteProcessMemory(
                hprocess,
                lpbaseaddress,
                lpbuffer,
                nsize,
                lpnumberofbyteswritten,
            )
            .as_bool()
        }
    }
}
pub mod process {
    use std::error::Error;

    use windows::Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                CREATE_TOOLHELP_SNAPSHOT_FLAGS, PROCESSENTRY32W,
            },
            Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS},
        },
    };

    use super::win32_err_string;

    #[inline]
    pub fn create_tool_help_32_snapshot(
        dwflags: u32,
        th32processid: u32,
    ) -> Result<HANDLE, Box<dyn Error>> {
        let res = unsafe {
            CreateToolhelp32Snapshot(CREATE_TOOLHELP_SNAPSHOT_FLAGS(dwflags), th32processid)
        };

        match res {
            Ok(res) => Ok(res),
            Err(err) => Err(win32_err_string(err.code()).into()),
        }
    }

    #[inline]
    pub fn process_32_first_w(hsnapshot: HANDLE, lppe: &mut PROCESSENTRY32W) -> bool {
        let res = unsafe { Process32FirstW(hsnapshot, lppe) };
        res.as_bool()
    }

    #[inline]
    pub fn process_32_next_w(hsnapshot: HANDLE, lppe: &mut PROCESSENTRY32W) -> bool {
        let res = unsafe { Process32NextW(hsnapshot, lppe) };
        res.as_bool()
    }

    #[inline]
    pub fn open_process(
        dwdesiredaccess: u32,
        binherithandle: bool,
        dwprocessid: u32,
    ) -> Result<HANDLE, Box<dyn Error>> {
        let dwdesiredaccess = PROCESS_ACCESS_RIGHTS(dwdesiredaccess);
        let res = unsafe { OpenProcess(dwdesiredaccess, binherithandle, dwprocessid) };

        match res {
            Ok(res) => Ok(res),
            Err(err) => Err(win32_err_string(err.code()).into()),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    pub fn test() {}
}
