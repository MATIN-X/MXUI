package com.mxui.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

class MxuiVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private var running = false

    companion object {
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "mxui_vpn_channel"
        const val ACTION_CONNECT = "com.mxui.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.mxui.vpn.DISCONNECT"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val config = intent.getStringExtra("config")
                startVpn(config)
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_STICKY
    }

    private fun startVpn(config: String?) {
        if (running) return
        running = true

        // Show notification
        showNotification("Connected", "VPN is running")

        // Build VPN interface
        val builder = Builder()
        builder.setSession("MX-UI VPN")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.addDnsServer("8.8.8.8")
        builder.addDnsServer("1.1.1.1")

        // Create VPN interface
        vpnInterface = builder.establish()

        // Start VPN thread
        vpnThread = Thread {
            runVpnLoop()
        }
        vpnThread?.start()
    }

    private fun runVpnLoop() {
        val vpnInput = FileInputStream(vpnInterface?.fileDescriptor)
        val vpnOutput = FileOutputStream(vpnInterface?.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767)
        val packet = ByteArray(32767)

        try {
            // This is a simplified VPN loop
            // In production, you would:
            // 1. Parse packets from vpnInput
            // 2. Forward to remote VPN server
            // 3. Receive responses from server
            // 4. Write responses to vpnOutput

            while (running) {
                // Read packet from VPN interface
                val length = vpnInput.read(packet)
                if (length > 0) {
                    // In production: send packet to VPN server
                    // For now, we just drop it
                }

                Thread.sleep(10)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            vpnInput.close()
            vpnOutput.close()
        }
    }

    private fun stopVpn() {
        running = false
        vpnThread?.interrupt()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(true)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun showNotification(title: String, content: String) {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        startForeground(NOTIFICATION_ID, notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    override fun onRevoke() {
        super.onRevoke()
        stopVpn()
    }
}
