using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace TelemetryAgent
{
    public class Program
    {
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            // Configure your Supabase project details here
            SupabaseConfig config = new SupabaseConfig
            {
                ProjectUrl = "https://qkvnvglkfixivqmzhhgc.supabase.co",
                ApiKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFrdm52Z2xrZml4aXZxbXpoaGdjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDEwOTkxMjAsImV4cCI6MjA1NjY3NTEyMH0.UTWoOTwEVM9Y7beGiYlPUu579RwMneEuGdWZvK7d8ok",
                TableName = "endpoint_telemetry"
            };
            
            TelemetryAgent agent = new TelemetryAgent(config, 300);
            
            Application.Run(new TelemetryTrayApplication(agent));
        }
    }

    public class SupabaseConfig
    {
        public string ProjectUrl { get; set; }
        public string ApiKey { get; set; }
        public string TableName { get; set; }
    }

    public class TelemetryTrayApplication : ApplicationContext
    {
        private NotifyIcon trayIcon;
        private TelemetryAgent agent;
        private CancellationTokenSource cts;

        public TelemetryTrayApplication(TelemetryAgent agent)
        {
            this.agent = agent;
            this.cts = new CancellationTokenSource();

            // Initialize tray icon
            trayIcon = new NotifyIcon()
            {
                Icon = SystemIcons.Application,
                ContextMenuStrip = new ContextMenuStrip(),
                Visible = true,
                Text = "Telemetry Agent"
            };

            // Add menu items
            trayIcon.ContextMenuStrip.Items.Add("Start Monitoring", null, StartMonitoring);
            trayIcon.ContextMenuStrip.Items.Add("Stop Monitoring", null, StopMonitoring);
            trayIcon.ContextMenuStrip.Items.Add("Send Now", null, SendNow);
            trayIcon.ContextMenuStrip.Items.Add("Settings", null, ShowSettings);
            trayIcon.ContextMenuStrip.Items.Add("View Logs", null, ViewLogs);
            trayIcon.ContextMenuStrip.Items.Add("-"); // Separator
            trayIcon.ContextMenuStrip.Items.Add("Exit", null, Exit);

            // Start monitoring automatically
            StartMonitoring(null, null);
        }

        private void StartMonitoring(object sender, EventArgs e)
        {
            if (!agent.IsRunning)
            {
                agent.Start(cts.Token);
                trayIcon.ShowBalloonTip(3000, "Telemetry Agent", "Monitoring started", ToolTipIcon.Info);
            }
        }

        private void StopMonitoring(object sender, EventArgs e)
        {
            if (agent.IsRunning)
            {
                agent.Stop();
                trayIcon.ShowBalloonTip(3000, "Telemetry Agent", "Monitoring stopped", ToolTipIcon.Info);
            }
        }

        private async void SendNow(object sender, EventArgs e)
        {
            trayIcon.ShowBalloonTip(3000, "Telemetry Agent", "Collecting and sending data...", ToolTipIcon.Info);
            
            try
            {
                var telemetry = agent.CollectTelemetry();
                bool success = await agent.SendTelemetryToSupabaseAsync(telemetry);
                
                if (success)
                    trayIcon.ShowBalloonTip(3000, "Telemetry Agent", "Data sent successfully to Supabase", ToolTipIcon.Info);
                else
                    trayIcon.ShowBalloonTip(3000, "Telemetry Agent", "Failed to send data to Supabase", ToolTipIcon.Error);
            }
            catch (Exception ex)
            {
                trayIcon.ShowBalloonTip(3000, "Telemetry Agent", $"Error: {ex.Message}", ToolTipIcon.Error);
                Logger.LogError(ex.ToString());
            }
        }

        private void ShowSettings(object sender, EventArgs e)
        {
            // Implementation for settings dialog would go here
            MessageBox.Show("Settings dialog not implemented yet.", "Settings", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ViewLogs(object sender, EventArgs e)
        {
            try
            {
                Process.Start(Logger.LogPath);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not open log file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Exit(object sender, EventArgs e)
        {
            // Clean up before exiting
            trayIcon.Visible = false;
            cts.Cancel();
            agent.Stop();
            Application.Exit();
        }
    }

    public class TelemetryAgent
    {
        private readonly SupabaseConfig supabaseConfig;
        private readonly int interval;
        private Task monitoringTask;
        private HttpClient httpClient;

        public bool IsRunning => monitoringTask != null && !monitoringTask.IsCompleted;

        public TelemetryAgent(SupabaseConfig config, int intervalSeconds)
        {
            this.supabaseConfig = config;
            this.interval = intervalSeconds;
            
            this.httpClient = new HttpClient();
            this.httpClient.BaseAddress = new Uri(config.ProjectUrl);
            this.httpClient.DefaultRequestHeaders.Accept.Clear();
            this.httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            this.httpClient.DefaultRequestHeaders.Add("apikey", config.ApiKey);
            this.httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {config.ApiKey}");
        }

        public void Start(CancellationToken cancellationToken)
        {
            if (IsRunning)
                return;

            monitoringTask = Task.Run(async () =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var telemetry = CollectTelemetry();
                        await SendTelemetryToSupabaseAsync(telemetry);
                        Logger.LogInfo("Telemetry data sent successfully to Supabase");
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError($"Error in telemetry collection or sending: {ex.Message}");
                    }

                    await Task.Delay(TimeSpan.FromSeconds(interval), cancellationToken);
                }
            }, cancellationToken);
        }

        public void Stop()
        {
            // The task will be terminated via cancellation token
        }

        public TelemetryData CollectTelemetry()
        {
            var telemetryData = new TelemetryData
            {
                DeviceInfo = CollectDeviceInfo(),
                NetworkInfo = CollectNetworkInfo(),
                SoftwareInfo = CollectSoftwareInfo(),
                SecurityInfo = CollectSecurityInfo(),
                EventLogs = CollectEventLogs()
            };

            Logger.LogInfo("Telemetry data collected successfully");
            return telemetryData;
        }

        public async Task<bool> SendTelemetryToSupabaseAsync(TelemetryData telemetry)
        {
            try
            {
                var telemetryRecord = new SupabaseTelemetryRecord
                {
                    CollectionTime = DateTime.Now,
                    DeviceId = Environment.MachineName,
                    TelemetryData = telemetry
                };

                string json = JsonSerializer.Serialize(telemetryRecord, new JsonSerializerOptions
                {
                    WriteIndented = false,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                string endpoint = $"/rest/v1/{supabaseConfig.TableName}";
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                
                httpClient.DefaultRequestHeaders.Remove("Prefer");
                httpClient.DefaultRequestHeaders.Add("Prefer", "return=minimal");

                var response = await httpClient.PostAsync(endpoint, content);
                
                if (!response.IsSuccessStatusCode)
                {
                    string errorResponse = await response.Content.ReadAsStringAsync();
                    Logger.LogError($"Supabase error: {response.StatusCode}, {errorResponse}");
                }

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Exception sending to Supabase: {ex.Message}");
                return false;
            }
        }

        private DeviceInfo CollectDeviceInfo()
        {
            var deviceInfo = new DeviceInfo
            {
                ComputerName = Environment.MachineName,
                OSVersion = Environment.OSVersion.ToString(),
                OSArchitecture = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit",
                UserName = Environment.UserName
            };

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        deviceInfo.CPUModel = obj["Name"].ToString();
                        deviceInfo.CPUCores = Convert.ToInt32(obj["NumberOfCores"]);
                        break;
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        deviceInfo.TotalRAM = Convert.ToInt64(obj["TotalPhysicalMemory"]) / (1024 * 1024);
                        break;
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        deviceInfo.StorageDevices.Add(new StorageDevice
                        {
                            Model = obj["Model"].ToString(),
                            Size = Convert.ToInt64(obj["Size"]) / (1024 * 1024 * 1024)
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error collecting device info: {ex.Message}");
            }

            return deviceInfo;
        }

        private NetworkInfo CollectNetworkInfo()
        {
            var networkInfo = new NetworkInfo();

            try
            {
                string hostName = Dns.GetHostName();
                networkInfo.HostName = hostName;

                IPAddress[] addresses = Dns.GetHostAddresses(hostName);
                foreach (var address in addresses)
                {
                    if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        networkInfo.IPAddresses.Add(address.ToString());
                    }
                }

                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var adapter = new NetworkAdapter
                        {
                            Name = nic.Name,
                            Description = nic.Description,
                            MACAddress = nic.GetPhysicalAddress().ToString(),
                            Status = nic.OperationalStatus.ToString()
                        };

                        IPInterfaceProperties properties = nic.GetIPProperties();
                        foreach (UnicastIPAddressInformation ip in properties.UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                adapter.IPAddress = ip.Address.ToString();
                                adapter.SubnetMask = ip.IPv4Mask.ToString();
                                break;
                            }
                        }

                        foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
                        {
                            adapter.Gateway = gateway.Address.ToString();
                            break;
                        }

                        networkInfo.Adapters.Add(adapter);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error collecting network info: {ex.Message}");
            }

            return networkInfo;
        }

        private SoftwareInfo CollectSoftwareInfo()
        {
            var softwareInfo = new SoftwareInfo();

            try
            {
                // Get installed software
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (key != null)
                    {
                        foreach (var subkeyName in key.GetSubKeyNames())
                        {
                            using (var subkey = key.OpenSubKey(subkeyName))
                            {
                                var displayName = subkey.GetValue("DisplayName") as string;
                                var displayVersion = subkey.GetValue("DisplayVersion") as string;

                                if (!string.IsNullOrEmpty(displayName))
                                {
                                    softwareInfo.InstalledSoftware.Add(new InstalledSoftware
                                    {
                                        Name = displayName,
                                        Version = displayVersion ?? "Unknown"
                                    });
                                }
                            }
                        }
                    }
                }

                // Get running processes
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        softwareInfo.RunningProcesses.Add(new RunningProcess
                        {
                            Name = process.ProcessName,
                            ID = process.Id,
                            Memory = process.WorkingSet64 / (1024 * 1024)
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error collecting software info: {ex.Message}");
            }

            return softwareInfo;
        }

        private SecurityInfo CollectSecurityInfo()
        {
            var securityInfo = new SecurityInfo();

            try
            {
                // Check BitLocker status
                using (var searcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_EncryptableVolume"))
                {
                    foreach (var volume in searcher.Get())
                    {
                        securityInfo.BitLockerVolumes.Add(new BitLockerVolume
                        {
                            DriveLetter = volume["DriveLetter"].ToString(),
                            EncryptionStatus = volume["EncryptionStatus"].ToString()
                        });
                    }
                }

                // Check Firewall status
                try
                {
                    using (var firewall = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM FirewallProduct"))
                    {
                        foreach (var fw in firewall.Get())
                        {
                            securityInfo.Firewall = new FirewallStatus
                            {
                                Name = fw["displayName"].ToString(),
                                Enabled = (Convert.ToInt32(fw["productState"]) & 0x1000) != 0
                            };
                            break;
                        }
                    }
                }
                catch
                {
                    // Fall back to Windows Firewall if SecurityCenter2 query fails
                    securityInfo.Firewall = new FirewallStatus
                    {
                        Name = "Windows Firewall",
                        Enabled = IsWindowsFirewallEnabled()
                    };
                }

                // Check Antivirus status
                try
                {
                    using (var antivirus = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct"))
                    {
                        foreach (var av in antivirus.Get())
                        {
                            securityInfo.Antivirus = new AntivirusStatus
                            {
                                Name = av["displayName"].ToString(),
                                Enabled = (Convert.ToInt32(av["productState"]) & 0x1000) != 0
                            };
                            break;
                        }
                    }
                }
                catch
                {
                    // Cannot determine AV status
                    securityInfo.Antivirus = new AntivirusStatus
                    {
                        Name = "Unknown",
                        Enabled = false
                    };
                }

                // Windows Update status simplified
                securityInfo.WindowsUpdateStatus = new WindowsUpdateStatus
                {
                    PendingUpdates = 0 // Simplified, would require COM interop in a real implementation
                };
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error collecting security info: {ex.Message}");
            }

            return securityInfo;
        }

        private bool IsWindowsFirewallEnabled()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"))
                {
                    if (key != null)
                    {
                        object value = key.GetValue("EnableFirewall");
                        if (value != null)
                        {
                            return Convert.ToBoolean(value);
                        }
                    }
                }
            }
            catch { }
            
            return false;
        }

        private List<EventLogEntry> CollectEventLogs()
        {
            var eventLogs = new List<EventLogEntry>();

            try
            {
                string[] logNames = { "Application", "System", "Security" };

                foreach (string logName in logNames)
                {
                    try
                    {
                        using (var eventLog = new EventLog(logName))
                        {
                            // Get the most recent 20 entries
                            var entries = eventLog.Entries.Cast<System.Diagnostics.EventLogEntry>()
                                .OrderByDescending(e => e.TimeGenerated)
                                .Take(20);

                            foreach (var entry in entries)
                            {
                                // Only include warnings and errors
                                if (entry.EntryType == EventLogEntryType.Error || entry.EntryType == EventLogEntryType.Warning)
                                {
                                    eventLogs.Add(new EventLogEntry
                                    {
                                        LogName = logName,
                                        EntryType = entry.EntryType.ToString(),
                                        Source = entry.Source,
                                        EventID = entry.EventID,
                                        Message = entry.Message,
                                        TimeGenerated = entry.TimeGenerated
                                    });
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError($"Error accessing {logName} log: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error collecting event logs: {ex.Message}");
            }

            return eventLogs;
        }
    }

    // Supabase specific record structure
    public class SupabaseTelemetryRecord
    {
        public DateTime CollectionTime { get; set; }
        public string DeviceId { get; set; }
        public TelemetryData TelemetryData { get; set; }
    }

    // Data models for telemetry
    public class TelemetryData
    {
        public DeviceInfo DeviceInfo { get; set; }
        public NetworkInfo NetworkInfo { get; set; }
        public SoftwareInfo SoftwareInfo { get; set; }
        public SecurityInfo SecurityInfo { get; set; }
        public List<EventLogEntry> EventLogs { get; set; }
    }

    public class DeviceInfo
    {
        public string ComputerName { get; set; }
        public string OSVersion { get; set; }
        public string OSArchitecture { get; set; }
        public string UserName { get; set; }
        public string CPUModel { get; set; }
        public int CPUCores { get; set; }
        public long TotalRAM { get; set; } // MB
        public List<StorageDevice> StorageDevices { get; set; } = new List<StorageDevice>();
    }

    public class StorageDevice
    {
        public string Model { get; set; }
        public long Size { get; set; } // GB
    }

    public class NetworkInfo
    {
        public string HostName { get; set; }
        public List<string> IPAddresses { get; set; } = new List<string>();
        public List<NetworkAdapter> Adapters { get; set; } = new List<NetworkAdapter>();
    }

    public class NetworkAdapter
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string MACAddress { get; set; }
        public string Status { get; set; }
        public string IPAddress { get; set; }
        public string SubnetMask { get; set; }
        public string Gateway { get; set; }
    }

    public class SoftwareInfo
    {
        public List<InstalledSoftware> InstalledSoftware { get; set; } = new List<InstalledSoftware>();
        public List<RunningProcess> RunningProcesses { get; set; } = new List<RunningProcess>();
    }

    public class InstalledSoftware
    {
        public string Name { get; set; }
        public string Version { get; set; }
    }

    public class RunningProcess
    {
        public string Name { get; set; }
        public int ID { get; set; }
        public long Memory { get; set; } // MB
    }

    public class SecurityInfo
    {
        public FirewallStatus Firewall { get; set; }
        public AntivirusStatus Antivirus { get; set; }
        public WindowsUpdateStatus WindowsUpdateStatus { get; set; }
        public List<BitLockerVolume> BitLockerVolumes { get; set; } = new List<BitLockerVolume>();
    }

    public class FirewallStatus
    {
        public string Name { get; set; }
        public bool Enabled { get; set; }
    }

    public class AntivirusStatus
    {
        public string Name { get; set; }
        public bool Enabled { get; set; }
    }

    public class WindowsUpdateStatus
    {
        public int PendingUpdates { get; set; }
    }

    public class BitLockerVolume
    {
        public string DriveLetter { get; set; }
        public string EncryptionStatus { get; set; }
    }

    public class EventLogEntry
    {
        public string LogName { get; set; }
        public string EntryType { get; set; }
        public string Source { get; set; }
        public int EventID { get; set; }
        public string Message { get; set; }
        public DateTime TimeGenerated { get; set; }
    }

    // Simple logger
    public static class Logger
    {
        public static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "TelemetryAgent",
            "logs.txt");

        static Logger()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath));
        }

        public static void LogInfo(string message)
        {
            Log("INFO", message);
        }

        public static void LogError(string message)
        {
            Log("ERROR", message);
        }

        private static void Log(string level, string message)
        {
            try
            {
                string logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}";
                File.AppendAllText(LogPath, logMessage + Environment.NewLine);
            }
            catch { }
        }
    }
}
