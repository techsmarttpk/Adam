using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Threading;
using Microsoft.Win32;

namespace AdamMutationTest
{
    class Program
    {
        private const string Version = "1.0.0";
        private const string HarnessVersion = "1.0.0";
        private const string ManifestVersion = "2026.1";

        static int Main(string[] args)
        {
            Console.WriteLine("=================================================");
            Console.WriteLine(" [ADAM-MUTATION-TEST] Diagnostic Harness");
            Console.WriteLine(" Version: " + Version + " | Harness: " + HarnessVersion + " | Manifest: " + ManifestVersion);
            Console.WriteLine(" Notice: Safe deterministic telemetry triggers only.");
            Console.WriteLine("=================================================");

            if (args.Length == 0 || args[0] == "--help" || args[0] == "-h")
            {
                PrintUsage();
                return 0;
            }

            string command = "";
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--cmd" && i + 1 < args.Length)
                {
                    command = args[i + 1].ToLowerInvariant();
                    break;
                }
                else if (!args[i].StartsWith("--"))
                {
                    command = args[i].ToLowerInvariant();
                    break;
                }
            }

            if (string.IsNullOrEmpty(command))
            {
                Console.WriteLine("[!] No command specified.");
                PrintUsage();
                return 1;
            }

            Console.WriteLine("[*] Executing test trigger: " + command);
            try
            {
                switch (command)
                {
                    // --- CRITICAL ---
                    case "vm_check":
                        TriggerVmCheck();
                        break;
                    case "process_hollowing":
                        TriggerProcessHollowing();
                        break;
                    case "cloud_creds":
                        TriggerCloudCreds();
                        break;
                    case "c2_dga":
                        TriggerC2Dga();
                        break;
                    case "shadow_copy_delete":
                        TriggerShadowCopyDelete();
                        break;
                    case "rdp_lateral":
                        TriggerRdpLateral();
                        break;

                    // --- HIGH ---
                    case "recon_dc":
                        TriggerReconDc();
                        break;
                    case "browser_creds":
                        TriggerBrowserCreds();
                        break;
                    case "crypto_wallet":
                        TriggerCryptoWallet();
                        break;
                    case "ssh_keys":
                        TriggerSshKeys();
                        break;
                    case "admin_shares":
                        TriggerAdminShares();
                        break;
                    case "c2_beacon":
                        TriggerC2Beacon();
                        break;

                    // --- MEDIUM ---
                    case "process_discovery":
                        TriggerProcessDiscovery();
                        break;
                    case "user_discovery":
                        TriggerUserDiscovery();
                        break;
                    case "installed_software":
                        TriggerInstalledSoftware();
                        break;

                    // --- LOW / OBSERVE ---
                    case "system_info":
                        TriggerSystemInfo();
                        break;
                    case "network_config":
                        TriggerNetworkConfig();
                        break;
                    case "lsass_access":
                        TriggerLsassAccess();
                        break;

                    default:
                        Console.WriteLine("[-] Unknown test command: " + command);
                        return 2;
                }

                Console.WriteLine("[+] Completed trigger execution for: " + command);
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Execution error: " + ex.Message);
                return 3;
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("Usage: adam_mutation_test.exe --cmd <command_id>");
            Console.WriteLine("Available commands:");
            Console.WriteLine("  CRITICAL : vm_check, process_hollowing, cloud_creds, c2_dga, shadow_copy_delete, rdp_lateral");
            Console.WriteLine("  HIGH     : recon_dc, browser_creds, crypto_wallet, ssh_keys, admin_shares, c2_beacon");
            Console.WriteLine("  MEDIUM   : process_discovery, user_discovery, installed_software");
            Console.WriteLine("  LOW/OBS  : system_info, network_config, lsass_access");
        }

        // =========================================================================
        // SAFE TRIGGER IMPLEMENTATIONS
        // =========================================================================

        static void RunProcess(string filename, string arguments)
        {
            try
            {
                Process p = Process.Start(new ProcessStartInfo(filename, arguments)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                if (p != null)
                {
                    p.WaitForExit(3000);
                }
            }
            catch {}
        }

        static void TriggerVmCheck()
        {
            Console.WriteLine(" -> Querying System BIOS and Video BIOS registry keys for VM descriptors...");
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System"))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("SystemBiosVersion");
                        Console.WriteLine("    [OK] Read SystemBiosVersion: " + (val != null ? string.Join(",", (string[])val) : "null"));
                    }
                }
            }
            catch {}
        }

        static void TriggerProcessHollowing()
        {
            Console.WriteLine(" -> Emitting process hollowing command line diagnostic signature...");
            RunProcess("cmd.exe", "/c echo [ADAM_TEST] process hollowing test signature");
        }

        static void TriggerCloudCreds()
        {
            Console.WriteLine(" -> Querying .aws/credentials path...");
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string awsPath = Path.Combine(userProfile, @".aws\credentials");
            bool exists = File.Exists(awsPath);
            Console.WriteLine("    [OK] Checked path: " + awsPath + " (exists: " + exists + ")");
        }

        static void TriggerC2Dga()
        {
            Console.WriteLine(" -> Initiating probe to pseudo-random DGA domain (xk83jf92md01ks83.biz)...");
            try
            {
                Dns.GetHostAddresses("xk83jf92md01ks83.biz");
            }
            catch (Exception)
            {
                Console.WriteLine("    [OK] DGA query triggered (expected host unreachable)");
            }
        }

        static void TriggerShadowCopyDelete()
        {
            Console.WriteLine(" -> Triggering diagnostic shadow copy deletion query...");
            RunProcess("cmd.exe", "/c echo [ADAM_TEST] vssadmin delete shadows /all /quiet");
        }

        static void TriggerRdpLateral()
        {
            Console.WriteLine(" -> Initiating outbound TCP check on port 3389...");
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    client.ConnectAsync("192.168.1.55", 3389).Wait(500);
                }
            }
            catch
            {
                Console.WriteLine("    [OK] Outbound port 3389 socket probe dispatched");
            }
        }

        static void TriggerReconDc()
        {
            Console.WriteLine(" -> Querying Domain Controller parameters via nltest query signature...");
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"))
                {
                    if (key != null)
                    {
                        object domain = key.GetValue("Domain");
                        Console.WriteLine("    [OK] Read Tcpip Domain: " + domain);
                    }
                }
            }
            catch {}
            RunProcess("cmd.exe", "/c echo [ADAM_TEST] nltest /dclist:CORP");
        }

        static void TriggerBrowserCreds()
        {
            Console.WriteLine(" -> Probing Google Chrome Login Data vault path...");
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string loginData = Path.Combine(localAppData, @"Google\Chrome\User Data\Default\Login Data");
            bool exists = File.Exists(loginData);
            Console.WriteLine("    [OK] Probed path: " + loginData + " (exists: " + exists + ")");
        }

        static void TriggerCryptoWallet()
        {
            Console.WriteLine(" -> Probing Electrum wallet directory...");
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string walletDir = Path.Combine(appData, @"Electrum\wallets");
            bool exists = Directory.Exists(walletDir);
            Console.WriteLine("    [OK] Probed wallet directory: " + walletDir + " (exists: " + exists + ")");
        }

        static void TriggerSshKeys()
        {
            Console.WriteLine(" -> Probing ~/.ssh/id_rsa private key location...");
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string keyPath = Path.Combine(userProfile, @".ssh\id_rsa");
            bool exists = File.Exists(keyPath);
            Console.WriteLine("    [OK] Probed key path: " + keyPath + " (exists: " + exists + ")");
        }

        static void TriggerAdminShares()
        {
            Console.WriteLine(" -> Probing for administrative share C$ / ADMIN$...");
            RunProcess("cmd.exe", @"/c echo [ADAM_TEST] net view \\127.0.0.1\c$");
        }

        static void TriggerC2Beacon()
        {
            Console.WriteLine(" -> Transmitting synthetic HTTP C2 beacon...");
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://198.51.100.42:8080/api/stage");
                req.Timeout = 1000;
                req.Method = "GET";
                using (WebResponse resp = req.GetResponse()) {}
            }
            catch
            {
                Console.WriteLine("    [OK] HTTP C2 beacon traffic emitted");
            }
        }

        static void TriggerProcessDiscovery()
        {
            Console.WriteLine(" -> Enumerating running processes...");
            RunProcess("cmd.exe", "/c tasklist");
        }

        static void TriggerUserDiscovery()
        {
            Console.WriteLine(" -> Querying current identity...");
            RunProcess("cmd.exe", "/c whoami");
        }

        static void TriggerInstalledSoftware()
        {
            Console.WriteLine(" -> Querying installed software registry keys...");
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (key != null)
                    {
                        Console.WriteLine("    [OK] Opened Uninstall subkey, subkeys count: " + key.SubKeyCount);
                    }
                }
            }
            catch {}
        }

        static void TriggerSystemInfo()
        {
            Console.WriteLine(" -> Querying system version info baseline...");
            RunProcess("cmd.exe", "/c winver");
        }

        static void TriggerNetworkConfig()
        {
            Console.WriteLine(" -> Querying network configuration interfaces...");
            RunProcess("cmd.exe", "/c ipconfig /all");
        }

        static void TriggerLsassAccess()
        {
            Console.WriteLine(" -> Querying LSASS process handle without memory dumping (Observe baseline)...");
            try
            {
                Process[] procs = Process.GetProcessesByName("lsass");
                if (procs.Length > 0)
                {
                    Console.WriteLine("    [OK] Observed LSASS PID: " + procs[0].Id);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("    [OK] LSASS query access: " + ex.Message);
            }
        }
    }
}
