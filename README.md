# TGP_SystemTray

Telemetry collection agent in system tray
Key Requirements for the Tray Agent
System Information Collection:


Device name, OS version, hardware specs (CPU, RAM, storage).


Network details (IP address, MAC address, Wi-Fi status).


Installed software & running processes.


Security status (Antivirus, Firewall, BitLocker encryption).


Event logs (errors, warnings, system crashes).


Compliance status (CE/CE+ related data).


Secure Communication with TGP:


API calls to send data (REST API/WebSocket).


Supabase/PostgreSQL integration for storage.


Encryption of data in transit (TLS 1.2/1.3).


Authentication (JWT token from TGP authentication system).


Background Service and UI:


Runs in the background as a Windows tray application.


Minimal UI (tray icon with a right-click menu for actions like "Send Report," "Settings," "Exit").


Auto-start on Windows boot.


Remote Management Capabilities (Future Phase):


Trigger alerts for outdated OS/software.


Remote commands (e.g., request logs, trigger diagnostic scans).


Secure software updates via TGP.
