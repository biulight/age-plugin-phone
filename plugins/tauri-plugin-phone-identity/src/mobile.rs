use serde::de::DeserializeOwned;
use tauri::{
    AppHandle, Runtime,
    plugin::{PluginApi, PluginHandle},
};

use crate::{AgreementReport, CapabilityReport, CleanupReport, Error, ProbeKeyReport};

const PLUGIN_IDENTIFIER: &str = "io.github.biulight.phone_identity";

pub struct PhoneIdentity<R: Runtime>(PluginHandle<R>);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> Result<PhoneIdentity<R>, Error> {
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "PhoneIdentityPlugin")?;
    Ok(PhoneIdentity(handle))
}

impl<R: Runtime> PhoneIdentity<R> {
    pub fn doctor_capabilities(&self) -> Result<CapabilityReport, Error> {
        self.0
            .run_mobile_plugin("doctorCapabilities", ())
            .map_err(Into::into)
    }

    pub fn doctor_create_probe(&self) -> Result<ProbeKeyReport, Error> {
        self.0
            .run_mobile_plugin("doctorCreateProbe", ())
            .map_err(Into::into)
    }

    pub fn doctor_run_agreement(&self) -> Result<AgreementReport, Error> {
        self.0
            .run_mobile_plugin("doctorRunAgreement", ())
            .map_err(Into::into)
    }

    pub fn doctor_cleanup(&self) -> Result<CleanupReport, Error> {
        self.0
            .run_mobile_plugin("doctorCleanup", ())
            .map_err(Into::into)
    }
}
