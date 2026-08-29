use serde::de::DeserializeOwned;
use tauri::{
    AppHandle, Runtime,
    plugin::{PluginApi, PluginHandle},
};

use crate::{
    AgreementReport, CapabilityReport, CleanupReport, Error, IdentityCustodyReport,
    IdentityStatusReport, LifecycleReport, PairingOfferScanReport, PairingStorageReport,
    PhonePairingReport, PhoneUnwrapReport, ProbeKeyReport,
};

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokePairingArgs {
    handle: String,
}

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

    pub fn doctor_identity_custody(&self) -> Result<IdentityCustodyReport, Error> {
        self.0
            .run_mobile_plugin("doctorIdentityCustody", ())
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

    pub fn doctor_pairing_storage(&self) -> Result<PairingStorageReport, Error> {
        self.0
            .run_mobile_plugin("doctorPairingStorage", ())
            .map_err(Into::into)
    }

    pub fn scan_pairing_offer(&self) -> Result<PairingOfferScanReport, Error> {
        self.0
            .run_mobile_plugin("scanPairingOffer", ())
            .map_err(Into::into)
    }

    pub fn pair_phone(&self) -> Result<PhonePairingReport, Error> {
        self.0
            .run_mobile_plugin("pairPhone", ())
            .map_err(Into::into)
    }

    pub fn pair_phone_usb(&self) -> Result<PhonePairingReport, Error> {
        self.0
            .run_mobile_plugin("pairPhoneUsb", ())
            .map_err(Into::into)
    }

    pub fn unwrap_phone(&self) -> Result<PhoneUnwrapReport, Error> {
        self.0
            .run_mobile_plugin("unwrapPhone", ())
            .map_err(Into::into)
    }

    pub fn identity_status(&self) -> Result<IdentityStatusReport, Error> {
        self.0
            .run_mobile_plugin("identityStatus", ())
            .map_err(Into::into)
    }

    pub fn provision_identity(&self) -> Result<IdentityStatusReport, Error> {
        self.0
            .run_mobile_plugin("provisionIdentity", ())
            .map_err(Into::into)
    }

    pub fn revoke_pairing(&self, handle: String) -> Result<LifecycleReport, Error> {
        self.0
            .run_mobile_plugin("revokePairing", RevokePairingArgs { handle })
            .map_err(Into::into)
    }

    pub fn delete_identity(&self) -> Result<LifecycleReport, Error> {
        self.0
            .run_mobile_plugin("deleteIdentity", ())
            .map_err(Into::into)
    }
}
