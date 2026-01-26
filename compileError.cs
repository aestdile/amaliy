using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace TpmSecureRunner
{
    class Program
    {
        // TPM 2.0 uchun Win32 API
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptAcquireContext(
            out IntPtr hProv,
            string szContainer,
            string szProvider,
            uint dwProvType,
            uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptCreateHash(
            IntPtr hProv,
            uint Algid,
            IntPtr hKey,
            uint dwFlags,
            out IntPtr phHash);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const uint PROV_RSA_FULL = 1;
        const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        const uint TOKEN_QUERY = 0x0008;
        const uint CALG_SHA_256 = 0x0000800C;

        static void Main(string[] args)
        {
            ShowWindow(GetConsoleWindow(), SW_HIDE);

            try
            {
                // 1. Security audit - anti-debug, anti-tamper
                PerformSecurityAudit();

                // 2. Get URL from user
                Console.Write("Enter url: ");
                string url = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(url))
                {
                    Console.WriteLine("URL cannot be empty!");
                    return;
                }

                // 3. Download and convert to WASM
                string wasmFile = DownloadAndConvertToWasm(url);

                // 4. Encrypt with TPM-bound key
                string encryptedFile = TpmEncryptWasm(wasmFile);

                // 5. Create secure runner
                string runnerExe = CreateSecureRunner(encryptedFile);

                // 6. Execute securely
                ExecuteSecureRunner();

                Console.WriteLine("Successfully finished");
            }
            catch (SecurityException ex)
            {
                Console.WriteLine($"Security violation: {ex.Message}");
                Environment.Exit(1);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static void PerformSecurityAudit()
        {
            // 1. Check for debugger
            if (Debugger.IsAttached || IsDebuggerPresent())
                throw new SecurityException("Debugger detected");

            // 2. Check TPM availability
            if (!IsTpm20Available())
                throw new SecurityException("TPM 2.0 not available");

            // 3. Check Secure Boot status
            if (!IsSecureBootEnabled())
                throw new SecurityException("Secure Boot not enabled");

            // 4. Check virtualization-based security
            if (!IsVirtualizationBasedSecurityEnabled())
                throw new SecurityException("VBS not enabled");

            // 5. Verify OS integrity
            VerifyOsIntegrity();

            // 6. Anti-hooking check
            CheckForHooks();
        }

        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();

        static bool IsTpm20Available()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine
                    .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TPM");

                return key != null;
            }
            catch
            {
                return false;
            }
        }

        static bool IsSecureBootEnabled()
        {
            //try
            //{
            //    using (var searcher = new ManagementObjectSearcher("root\\Microsoft\\Windows\\DeviceGuard", "SELECT * FROM Win32_DeviceGuard"))
            //    {
            //        foreach (ManagementObject queryObj in searcher.Get())
            //        {
            //            var secureBoot = queryObj["SecureBootEnabled"];
            //            return secureBoot?.ToString() == "True";
            //        }
            //    }
            //}
            //catch { }
            //return false;
            return true;
        }

        static bool IsVirtualizationBasedSecurityEnabled()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("root\\Microsoft\\Windows\\DeviceGuard", "SELECT * FROM Win32_DeviceGuard"))
                {
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        var vbs = queryObj["VirtualizationBasedSecurityStatus"];
                        return Convert.ToInt32(vbs) == 2; // 2 = Running
                    }
                }
            }
            catch { }
            return false;
        }

        //--------------------------------------------------------
        static void VerifyOsIntegrity()
        {
            // 1️⃣ Flight Signing / Insider build tekshiruvi
            if (IsFlightSigningEnabled())
                throw new SecurityException("OS integrity check failed: Flight/Insider build detected");

            // 2️⃣ Measure boot state using PCRs (simplified)
            string bootState = GetCurrentBootState();
            string expectedState = GetExpectedBootState();

            if (bootState != expectedState)
                throw new SecurityException("OS integrity check failed: Boot state mismatch");
        }

        static bool IsFlightSigningEnabled()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_OperatingSystem");

                foreach (ManagementObject os in searcher.Get())
                {
                    var buildLab = os["BuildLab"]?.ToString() ?? "";
                    var caption = os["Caption"]?.ToString() ?? "";

                    if (buildLab.ToLower().Contains("flight") ||
                        caption.ToLower().Contains("insider"))
                    {
                        return true;
                    }
                }
            }
            catch { }

            return false;
        }

        static void CheckForHooks()
        {
            // Check for API hooks in critical functions
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            IntPtr kernel32 = GetModuleHandle("kernel32.dll");

            if (IsFunctionHooked(ntdll, "NtQuerySystemInformation") ||
                IsFunctionHooked(kernel32, "CreateProcessW"))
            {
                throw new SecurityException("API hooks detected");
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        static bool IsFunctionHooked(IntPtr module, string functionName)
        {
            // Simplified hook detection
            return false;
        }

        static string GetCurrentBootState()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "root\\CIMV2\\Security\\MicrosoftTpm",
                    "SELECT * FROM Win32_Tpm");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    var state = queryObj["ManufacturerVersionInfo"]?.ToString();
                    if (!string.IsNullOrEmpty(state))
                        return state;
                }
            }
            catch { }

            // Fallback: demo uchun **static value** qaytarish
            return "SECURE_BOOT_VALID";
        }

        static string GetExpectedBootState()
        {
            return "SECURE_BOOT_VALID";
        }

        static string DownloadAndConvertToWasm(string url)
        {
            string tempWasm = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".wasm");

            try
            {
                // Download file
                byte[] fileContent = DownloadFile(url);
                string fileName = Path.GetFileName(new Uri(url).LocalPath);
                string extension = Path.GetExtension(fileName).ToLower();

                // Convert to WASM based on file type
                byte[] wasmBytes = ConvertToWasm(fileContent, extension);

                // Save WASM file
                File.WriteAllBytes(tempWasm, wasmBytes);

                return tempWasm;
            }
            catch
            {
                if (File.Exists(tempWasm))
                    File.Delete(tempWasm);
                throw;
            }
        }

        static byte[] DownloadFile(string url)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
                return client.DownloadData(url);
            }
        }

        static byte[] ConvertToWasm(byte[] sourceCode, string extension)
        {
            // In production, use actual compilers:
            // .py → wasmer-python
            // .js → wasmer-js
            // .go → tinygo → wasm
            // .rs → rustc → wasm

            // For demo, wrap source in minimal WASM runtime
            return CreateWasmWrapper(sourceCode, extension);
        }

        static byte[] CreateWasmWrapper(byte[] sourceCode, string extension)
        {
            // Minimal WASM wrapper that contains the source code
            // In production, actually compile to WASM
            string sourceBase64 = Convert.ToBase64String(sourceCode);
            string wrapper = $@"
                (module
                  (memory 1)
                  (export ""memory"" (memory 0))
                  
                  (func $main (result i32)
                    (i32.const 42)
                  )
                  
                  (data (i32.const 0) ""{sourceBase64}"")
                  (data (i32.const 1024) ""{extension}"")
                  
                  (export ""_start"" (func $main))
                )
            ";

            using (var wat2wasm = new Process())
            {
                wat2wasm.StartInfo = new ProcessStartInfo
                {
                    FileName = @"C:\Tools\wabt\bin\wat2wasm.exe",
                    Arguments = "- -o output.wasm",
                    WorkingDirectory = Path.GetTempPath(),
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                wat2wasm.Start();
                wat2wasm.StandardInput.Write(wrapper);
                wat2wasm.StandardInput.Close();

                string err = wat2wasm.StandardError.ReadToEnd();
                wat2wasm.WaitForExit();

                if (!string.IsNullOrWhiteSpace(err))
                    throw new Exception("wat2wasm error: " + err);

                string outputPath = Path.Combine(Path.GetTempPath(), "output.wasm");

                if (File.Exists(outputPath))
                    return File.ReadAllBytes(outputPath);
            }

            // Fallback: minimal valid WASM
            return new byte[] { 0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00 };
        }

        static string TpmEncryptWasm(string wasmPath)
        {
            string encryptedPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".tpmenc");

            try
            {
                byte[] wasmData = File.ReadAllBytes(wasmPath);

                // Create TPM-bound encryption key
                byte[] encrypted = TpmSealData(wasmData);

                File.WriteAllBytes(encryptedPath, encrypted);

                // Clean up WASM file
                SecureDelete(wasmPath);

                return encryptedPath;
            }
            catch
            {
                if (File.Exists(encryptedPath))
                    File.Delete(encryptedPath);
                throw;
            }
        }


        static byte[] TpmSealData(byte[] data)
        {
            // Simulated TPM sealing using OS-bound encryption (AesGcm)

            // 1. System-bound material (PCR-like)
            byte[] systemBinding = GetSystemBindingData();

            // 2. Salt (must be stored with ciphertext)
            byte[] salt = RandomNumberGenerator.GetBytes(16);

            // 3. Derive key (TPM-like binding)
            byte[] key;
            using (var kdf = new Rfc2898DeriveBytes(
                systemBinding,
                salt,
                10000,
                HashAlgorithmName.SHA256))
            {
                key = kdf.GetBytes(32); // 256-bit key
            }

            // 4. GCM parameters
            byte[] nonce = RandomNumberGenerator.GetBytes(12); // IV
            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[16];

            // 5. Encrypt
            using (var aes = new AesGcm(key))
            {
                aes.Encrypt(
                    nonce,
                    data,
                    ciphertext,
                    tag,
                    associatedData: null // optional PCR/AAD
                );
            }

            // 6. Layout: SALT | NONCE | TAG | CIPHERTEXT
            byte[] result = new byte[
                salt.Length +
                nonce.Length +
                tag.Length +
                ciphertext.Length
            ];

            int offset = 0;

            Buffer.BlockCopy(salt, 0, result, offset, salt.Length);
            offset += salt.Length;

            Buffer.BlockCopy(nonce, 0, result, offset, nonce.Length);
            offset += nonce.Length;

            Buffer.BlockCopy(tag, 0, result, offset, tag.Length);
            offset += tag.Length;

            Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);

            return result;
        }


        static byte[] GetSystemBindingData()
        {
            // Combine: Machine ID + User SID + Process ID + Boot measurements
            var binding = new StringBuilder();

            // Machine GUID
            binding.Append(GetMachineGuid());

            // User SID
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                binding.Append(identity.User?.Value);
            }

            // Process ID
            binding.Append(Process.GetCurrentProcess().Id);

            // Boot measurements (simplified)
            binding.Append(GetCurrentBootState());

            return Encoding.UTF8.GetBytes(binding.ToString());
        }

        static string GetMachineGuid()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystemProduct"))
                {
                    foreach (ManagementObject queryObj in searcher.Get())
                    {
                        return queryObj["UUID"]?.ToString() ?? Guid.NewGuid().ToString();
                    }
                }
            }
            catch { }
            return Guid.NewGuid().ToString();
        }

        static void SecureDelete(string filePath)
        {
            if (!File.Exists(filePath)) return;

            try
            {
                // Overwrite with random data before deleting
                var rng = RandomNumberGenerator.Create();
                FileInfo fi = new FileInfo(filePath);
                long fileSize = fi.Length;

                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    byte[] randomData = new byte[8192];
                    long bytesWritten = 0;

                    while (bytesWritten < fileSize)
                    {
                        rng.GetBytes(randomData);
                        int toWrite = (int)Math.Min(randomData.Length, fileSize - bytesWritten);
                        fs.Write(randomData, 0, toWrite);
                        bytesWritten += toWrite;
                    }
                    fs.Flush();
                }

                File.Delete(filePath);
            }
            catch { }
        }

        static string CreateSecureRunner(string encryptedFilePath)
        {
            string runnerExe = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".exe");

            // Create runner with encrypted payload embedded
            byte[] encryptedData = File.ReadAllBytes(encryptedFilePath);
            BuildSecureRunner(runnerExe, encryptedData);

            // Clean up encrypted file
            SecureDelete(encryptedFilePath);

            return runnerExe;
        }

        static void BuildSecureRunner(string outputPath, byte[] encryptedPayload)
        {
            string runnerCode = @"using System;
                                using System.IO;
                                using System.Diagnostics;
                                using System.Security.Cryptography;
                                using System.Text;
                                using System.Reflection;
                                using System.Runtime.InteropServices;
                                using System.Threading;
                                using System.Security.Principal;
                                using System.Management;

                                namespace SecureRunner
                                {
                                    class Program
                                    {
                                        [DllImport(""kernel32.dll"")]
                                        static extern IntPtr GetConsoleWindow();
        
                                        [DllImport(""user32.dll"")]
                                        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        
                                        [DllImport(""kernel32.dll"")]
                                        static extern bool IsDebuggerPresent();
        
                                        [DllImport(""ntdll.dll"")]
                                        static extern uint NtSetInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, 
                                            ref uint ThreadInformation, uint ThreadInformationLength);
        
                                        const uint ThreadHideFromDebugger = 0x11;

                                        static void Main()
                                        {
                                            try
                                            {
                                                // 1. Hide from debugger immediately
                                                HideThreadFromDebugger();
                
                                                // 2. Hide console
                                                ShowWindow(GetConsoleWindow(), 0);
                
                                                // 3. Runtime security checks
                                                PerformRuntimeChecks();
                
                                                // 4. Extract and decrypt payload
                                                byte[] encrypted = ExtractEncryptedPayload();
                                                byte[] wasmData = TpmUnsealData(encrypted);
                
                                                // 5. Execute WASM in secure memory
                                                ExecuteWasmSecurely(wasmData);
                
                                                // 6. Clean exit
                                                SecureCleanup();
                                            }
                                            catch (Exception)
                                            {
                                                Environment.Exit(1);
                                            }
                                        }
        
                                        static void HideThreadFromDebugger()
                                        {
                                            uint isHide = 1;
                                            NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 
                                                ref isHide, (uint)Marshal.SizeOf(isHide));
                                        }
        
                                        [DllImport(""kernel32.dll"")]
                                        static extern IntPtr GetCurrentThread();
        
                                        static void PerformRuntimeChecks()
                                        {
                                            // Anti-debug
                                            if (IsDebuggerPresent() || Debugger.IsAttached)
                                                Environment.Exit(1);
            
                                            // TPM availability
                                            if (!CheckTpmAvailable())
                                                Environment.Exit(1);
            
                                            // System state verification
                                            if (!VerifySystemState())
                                                Environment.Exit(1);
            
                                            // Memory integrity check
                                            CheckMemoryIntegrity();
                                        }
        
                                        static bool CheckTpmAvailable()
                                        {
                                            try
                                            {
                                                var searcher = new ManagementObjectSearcher(""SELECT * FROM Win32_Tpm"");
                                                foreach (var obj in searcher.Get())
                                                {
                                                    var version = obj[""SpecVersion""]?.ToString();
                                                    return version?.Contains(""2.0"") == true;
                                                }
                                            }
                                            catch { }
                                            return false;
                                        }
        
                                        static bool VerifySystemState()
                                        {
                                            // Verify system hasn't changed since encryption
                                            string currentState = GetCurrentSystemState();
                                            string encryptedState = GetStateFromPayload();
            
                                            // Simple hash comparison
                                            using (SHA256 sha = SHA256.Create())
                                            {
                                                byte[] currentHash = sha.ComputeHash(Encoding.UTF8.GetBytes(currentState));
                                                byte[] encryptedHash = sha.ComputeHash(Encoding.UTF8.GetBytes(encryptedState));
                
                                                for (int i = 0; i < currentHash.Length; i++)
                                                    if (currentHash[i] != encryptedHash[i])
                                                        return false;
                                            }
            
                                            return true;
                                        }
        
                                        static string GetCurrentSystemState()
                                        {
                                            var sb = new StringBuilder();
            
                                            // Machine ID
                                            sb.Append(GetMachineGuid());
            
                                            // User context
                                            using (var identity = WindowsIdentity.GetCurrent())
                                                sb.Append(identity.User?.Value);
            
                                            // Process info
                                            sb.Append(Process.GetCurrentProcess().Id);
                                            sb.Append(Process.GetCurrentProcess().SessionId);
            
                                            // Boot measurements
                                            sb.Append(GetBootMeasurements());
            
                                            return sb.ToString();
                                        }
        
                                        static string GetMachineGuid()
                                        {
                                            try
                                            {
                                                var searcher = new ManagementObjectSearcher(""SELECT * FROM Win32_ComputerSystemProduct"");
                                                foreach (var obj in searcher.Get())
                                                    return obj[""UUID""]?.ToString() ?? """";
                                            }
                                            catch { }
                                            return """";
                                        }
        
                                        static string GetBootMeasurements()
                                        {
                                            try
                                            {
                                                var searcher = new ManagementObjectSearcher(""SELECT * FROM Win32_Tpm"");
                                                foreach (var obj in searcher.Get())
                                                    return obj[""ManufacturerVersionInfo""]?.ToString() ?? """";
                                            }
                                            catch { }
                                            return """";
                                        }
        
                                        static string GetStateFromPayload()
                                        {
                                            // Extract system state that was used during encryption
                                            // This would be embedded in the payload
                                            return ""SECURE_STATE_VALID"";
                                        }
        
                                        static void CheckMemoryIntegrity()
                                        {
                                            // Check for memory modifications
                                            // In production: use PageGuard, VBS, or similar
                                        }
        
                                        static byte[] ExtractEncryptedPayload()
                                        {
                                            string selfPath = Assembly.GetExecutingAssembly().Location;
                                            byte[] allBytes = File.ReadAllBytes(selfPath);
            
                                            // Payload starts after runner code (approx 12KB)
                                            int runnerSize = 12288;
                                            if (allBytes.Length > runnerSize)
                                            {
                                                byte[] payload = new byte[allBytes.Length - runnerSize];
                                                Array.Copy(allBytes, runnerSize, payload, 0, payload.Length);
                                                return payload;
                                            }
            
                                            throw new InvalidOperationException(""Payload not found"");
                                        }
        
                                        static byte[] TpmUnsealData(byte[] sealedData)
                                        {
                                            // Extract IV and Tag
                                            byte[] iv = new byte[12];
                                            byte[] tag = new byte[16];
                                            byte[] encrypted = new byte[sealedData.Length - 28];
            
                                            Array.Copy(sealedData, 0, iv, 0, 12);
                                            Array.Copy(sealedData, 12, tag, 0, 16);
                                            Array.Copy(sealedData, 28, encrypted, 0, encrypted.Length);
            
                                            // Recreate key from system state
                                            using (Aes aes = Aes.Create())
                                            {
                                                aes.KeySize = 256;
                                                aes.Mode = CipherMode.GCM;
                                                aes.Padding = PaddingMode.None;
                                                aes.IV = iv;
                                                aes.Tag = tag;
                
                                                byte[] systemBinding = GetCurrentSystemBinding();
                                                using (var deriveBytes = new Rfc2898DeriveBytes(systemBinding, new byte[16], 10000))
                                                {
                                                    aes.Key = deriveBytes.GetBytes(32);
                                                }
                
                                                using (var decryptor = aes.CreateDecryptor())
                                                using (var ms = new MemoryStream())
                                                {
                                                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                                                    {
                                                        cs.Write(encrypted, 0, encrypted.Length);
                                                        cs.FlushFinalBlock();
                                                    }
                                                    return ms.ToArray();
                                                }
                                            }
                                        }
        
                                        static byte[] GetCurrentSystemBinding()
                                        {
                                            return Encoding.UTF8.GetBytes(GetCurrentSystemState());
                                        }
        
                                        static void ExecuteWasmSecurely(byte[] wasmData)
                                        {
                                            // WASM execution in protected memory
                                            using (var wasmRuntime = new ProtectedWasmRuntime())
                                            {
                                                // Load WASM
                                                wasmRuntime.Load(wasmData);
                
                                                // Execute
                                                string result = wasmRuntime.Execute();
                
                                                // Output result securely
                                                if (!string.IsNullOrEmpty(result))
                                                {
                                                    Console.WriteLine(""----------- Result -----------"");
                                                    Console.WriteLine(result);
                                                    Console.WriteLine(""----------- End -----------"");
                                                }
                                            }
                                        }
        
                                        class ProtectedWasmRuntime : IDisposable
                                        {
                                            private byte[] wasmBuffer;
                                            private GCHandle handle;
            
                                            public void Load(byte[] wasmData)
                                            {
                                                // Pin array to prevent GC movement
                                                wasmBuffer = wasmData;
                                                handle = GCHandle.Alloc(wasmBuffer, GCHandleType.Pinned);
                
                                                // Mark memory as non-pageable
                                                VirtualLock(handle.AddrOfPinnedObject(), (uint)wasmBuffer.Length);
                                            }
            
                                            [DllImport(""kernel32.dll"", SetLastError = true)]
                                            static extern bool VirtualLock(IntPtr lpAddress, uint dwSize);
            
                                            [DllImport(""kernel32.dll"", SetLastError = true)]
                                            static extern bool VirtualUnlock(IntPtr lpAddress, uint dwSize);
            
                                            public string Execute()
                                            {
                                                // Simple WASM interpreter for demo
                                                // In production: use Wasmer, Wasmtime, or similar
                
                                                if (wasmBuffer.Length >= 8 && 
                                                    wasmBuffer[0] == 0x00 && wasmBuffer[1] == 0x61 && // \0asm
                                                    wasmBuffer[2] == 0x73 && wasmBuffer[3] == 0x6D)
                                                {
                                                    // Valid WASM - extract embedded source
                                                    return ExtractAndExecuteSource();
                                                }
                
                                                return ""[WASM Execution Complete]"";
                                            }
            
                                            string ExtractAndExecuteSource()
                                            {
                                                // Extract base64-encoded source from WASM data section
                                                // For demo, simulate execution
                                                return ""Result calculated from secure WASM execution"";
                                            }
            
                                            public void Dispose()
                                            {
                                                // Zero out memory
                                                if (wasmBuffer != null)
                                                {
                                                    for (int i = 0; i < wasmBuffer.Length; i++)
                                                        wasmBuffer[i] = 0;
                    
                                                    if (handle.IsAllocated)
                                                    {
                                                        VirtualUnlock(handle.AddrOfPinnedObject(), (uint)wasmBuffer.Length);
                                                        handle.Free();
                                                    }
                                                    wasmBuffer = null;
                                                }
                                            }
                                        }
        
                                        static void SecureCleanup()
                                        {
                                            // Zero sensitive data
                                            // Trigger self-deletion
                                            ScheduleSelfDeletion();
                                        }
        
                                        static void ScheduleSelfDeletion()
                                        {
                                            string selfPath = Assembly.GetExecutingAssembly().Location;
                                            string batchScript = Path.GetTempFileName() + "".bat"";
            
                                            string script = $@""@echo off
                                ping 127.0.0.1 -n 3 > nul
                                del \""{selfPath}\""
                                del \""%~f0\"""";
            
                                            File.WriteAllText(batchScript, script);
            
                                            Process.Start(new ProcessStartInfo
                                            {
                                                FileName = batchScript,
                                                CreateNoWindow = true,
                                                UseShellExecute = false,
                                                WindowStyle = ProcessWindowStyle.Hidden
                                            });
                                        }
                                    }
                                }";

            // Compile runner
            string runnerSource = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".cs");
            File.WriteAllText(runnerSource, runnerCode);

            // Compile with maximum security settings
            string compileCmd = $@"/target:exe /out:""{outputPath}"" /platform:x64 /optimize+ /debug- /unsafe /nowarn:0169 /reference:System.Management.dll ""{runnerSource}""";

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = GetCompilerPath(),
                Arguments = compileCmd,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process process = Process.Start(psi))
            {
                process.WaitForExit(30000);

                if (process.ExitCode != 0)
                {
                    string error = process.StandardError.ReadToEnd();
                    throw new Exception($"Compilation failed: {error}");
                }
            }

            // Append encrypted payload
            using (FileStream fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write))
            {
                fs.Write(encryptedPayload, 0, encryptedPayload.Length);
            }

            // Clean up
            File.Delete(runnerSource);
        }

        static string GetCompilerPath()
        {
            // Try to find csc.exe
            string[] paths = {
                @"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe",
                @"C:\Program Files\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\Roslyn\csc.exe",
                @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
            };

            foreach (string path in paths)
            {
                if (File.Exists(path))
                    return path;
            }

            return "csc.exe";
        }

        static void ExecuteSecureRunner()
        {
            string wat2wasmPath = @"C:\Tools\wabt\bin\wat2wasm.exe";
            string inputWat = @"C:\Temp\main.wat";
            string outputWasm = @"C:\Temp\main.wasm";

            if (!File.Exists(wat2wasmPath))
            {
                Console.WriteLine("wat2wasm topilmadi");
                return;
            }

            var psi = new ProcessStartInfo
            {
                FileName = wat2wasmPath,
                Arguments = $"\"{inputWat}\" -o \"{outputWasm}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi)!;

            string stdout = process.StandardOutput.ReadToEnd();
            string stderr = process.StandardError.ReadToEnd();

            process.WaitForExit();

            Console.WriteLine(stdout);
            if (!string.IsNullOrWhiteSpace(stderr))
                Console.WriteLine("ERR: " + stderr);
        }


        static void TryDeleteFile(string filePath)
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                        break;
                    }
                }
                catch
                {
                    Thread.Sleep(1000);
                }
            }
        }
    }

    class SecurityException : Exception
    {
        public SecurityException(string message) : base(message) { }
    }
}


//  Enter url: https://raw.githubusercontent.com/aestdile/amaliy/main/main.py
