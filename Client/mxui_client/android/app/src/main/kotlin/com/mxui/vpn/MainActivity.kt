package com.mxui.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "com.mxui.vpn/native"
    private val VPN_REQUEST_CODE = 100

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "prepareVpn" -> {
                    prepareVpn(result)
                }
                "startVpn" -> {
                    val config = call.argument<String>("config")
                    startVpn(config, result)
                }
                "stopVpn" -> {
                    stopVpn(result)
                }
                "getVpnState" -> {
                    getVpnState(result)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }

    private fun prepareVpn(result: MethodChannel.Result) {
        val intent = VpnService.prepare(applicationContext)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
            result.success(false)
        } else {
            result.success(true)
        }
    }

    private fun startVpn(config: String?, result: MethodChannel.Result) {
        if (config == null) {
            result.error("INVALID_CONFIG", "VPN config is null", null)
            return
        }

        val intent = Intent(this, MxuiVpnService::class.java)
        intent.putExtra("config", config)
        startService(intent)
        result.success(true)
    }

    private fun stopVpn(result: MethodChannel.Result) {
        val intent = Intent(this, MxuiVpnService::class.java)
        stopService(intent)
        result.success(true)
    }

    private fun getVpnState(result: MethodChannel.Result) {
        // In a real implementation, you would check the actual VPN state
        result.success("disconnected")
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                // VPN permission granted
            } else {
                // VPN permission denied
            }
        }
    }
}
