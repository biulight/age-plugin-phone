package io.github.biulight.age_plugin_phone

import android.content.Intent
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import io.github.biulight.phone_identity.UsbUnwrapWakeCoordinator
import io.github.biulight.phone_identity.WifiAutoListenForegroundCoordinator

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    UsbUnwrapWakeCoordinator.consume(intent)
  }

  override fun onStart() {
    super.onStart()
    WifiAutoListenForegroundCoordinator.onStart()
  }

  override fun onStop() {
    WifiAutoListenForegroundCoordinator.onStop()
    super.onStop()
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    UsbUnwrapWakeCoordinator.consume(intent)
  }
}
