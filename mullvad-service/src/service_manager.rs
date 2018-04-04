use std::ffi::OsStr;
use std::{io, ptr};

use shell_escape;
use widestring::WideCString;
use winapi::um::winsvc;

use service::{Service, ServiceAccess, ServiceInfo};

/// Enum describing access permissions for ServiceManager
#[derive(Builder, Debug)]
pub struct ServiceManagerAccess {
    /// Can connect to service control manager
    #[builder(default)]
    pub connect: bool,

    /// Can create services
    #[builder(default)]
    pub create_service: bool,

    /// Can enumerate services
    #[builder(default)]
    pub enumerate_service: bool,
}

impl ServiceManagerAccess {
    pub fn to_raw(&self) -> u32 {
        let mut mask: u32 = 0;

        if self.connect {
            mask |= winsvc::SC_MANAGER_CONNECT;
        }

        if self.create_service {
            mask |= winsvc::SC_MANAGER_CREATE_SERVICE;
        }

        if self.enumerate_service {
            mask |= winsvc::SC_MANAGER_ENUMERATE_SERVICE;
        }

        mask
    }
}

/// Service control manager
pub struct ServiceManager(winsvc::SC_HANDLE);

impl ServiceManager {
    /// Private initializer
    /// Passing None for machine connects to local machine
    /// Passing None for database connects to active database
    fn new<M: AsRef<OsStr>, D: AsRef<OsStr>>(
        machine: Option<M>,
        database: Option<D>,
        request_access: ServiceManagerAccess,
    ) -> io::Result<Self> {
        let machine_name = machine.map(|ref s| unsafe { WideCString::from_str_unchecked(s) });
        let database_name = database.map(|ref s| unsafe { WideCString::from_str_unchecked(s) });

        let handle = unsafe {
            winsvc::OpenSCManagerW(
                machine_name.map_or(ptr::null(), |s| s.as_ptr()),
                database_name.map_or(ptr::null(), |s| s.as_ptr()),
                request_access.to_raw(),
            )
        };

        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(ServiceManager(handle))
        }
    }

    /// Passing None for database connects to active database
    pub fn local_computer<T: AsRef<OsStr>>(
        database: Option<T>,
        request_access: ServiceManagerAccess,
    ) -> io::Result<Self> {
        ServiceManager::new(None::<&OsStr>, database, request_access)
    }

    /// Passing None for database connects to active database
    pub fn remote_computer<M: AsRef<OsStr>, D: AsRef<OsStr>>(
        machine: M,
        database: Option<D>,
        request_access: ServiceManagerAccess,
    ) -> io::Result<Self> {
        ServiceManager::new(Some(machine), database, request_access)
    }

    pub fn create_service(
        &self,
        service_info: ServiceInfo,
        request_access: ServiceAccess,
    ) -> io::Result<Service> {
        // escape executable path
        let launch_path =
            shell_escape::escape(service_info.executable_path.to_string_lossy()).into_owned();

        // escape and combine launch arguments in space separated string
        let launch_arguments = service_info
            .launch_arguments
            .into_iter()
            .map(|s| shell_escape::escape(s.into()).into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        // combine escaped executable path and launch arguments into one command
        let launch_command = vec![launch_path, launch_arguments].join(" ");

        let service_name = unsafe { WideCString::from_str_unchecked(service_info.name) };
        let display_name = unsafe { WideCString::from_str_unchecked(service_info.display_name) };
        let executable_path = unsafe { WideCString::from_str_unchecked(launch_command) };
        let account_name = service_info
            .account_name
            .map(|ref s| unsafe { WideCString::from_str_unchecked(s) });
        let account_password = service_info
            .account_password
            .map(|ref s| unsafe { WideCString::from_str_unchecked(s) });

        let service_handle = unsafe {
            winsvc::CreateServiceW(
                self.0,
                service_name.as_ptr(),
                display_name.as_ptr(),
                request_access.to_raw(),
                service_info.service_type.to_raw(),
                service_info.start_type.to_raw(),
                service_info.error_control.to_raw(),
                executable_path.as_ptr(),
                ptr::null(),     // load ordering group
                ptr::null_mut(), // tag id within the load ordering group
                ptr::null(),     // service dependencies
                account_name.map_or(ptr::null(), |s| s.as_ptr()),
                account_password.map_or(ptr::null(), |s| s.as_ptr()),
            )
        };

        if service_handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { Service::from_handle(service_handle) })
        }
    }

    pub fn open_service<T: AsRef<OsStr>>(
        &self,
        name: T,
        request_access: ServiceAccess,
    ) -> io::Result<Service> {
        let service_name = unsafe { WideCString::from_str_unchecked(name) };
        let service_handle =
            unsafe { winsvc::OpenServiceW(self.0, service_name.as_ptr(), request_access.to_raw()) };

        if service_handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { Service::from_handle(service_handle) })
        }
    }
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        unsafe { winsvc::CloseServiceHandle(self.0) };
    }
}
