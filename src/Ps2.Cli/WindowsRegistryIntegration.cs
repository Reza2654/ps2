using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Ps2.Cli;

public static class WindowsRegistryIntegration
{
    public static bool RegisterFileAssociation()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine("[INFO] Windows file association is only supported on Windows.");
            Console.WriteLine("[INFO] On Unix-like systems, ensure 'ps2' is in your PATH and use shebang: '#!/usr/bin/env ps2'");
            return false;
        }

        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(exePath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] Could not resolve ps2 executable path.");
            Console.ResetColor();
            return false;
        }

        try
        {
            // 1. Associate .ps2 extension with ProgID "ps2_script" in HKCU (works without admin rights!)
            RunRegCommand(@"add HKCU\Software\Classes\.ps2 /ve /d ps2_script /f");
            RunRegCommand(@"add HKCU\Software\Classes\.ps2 /v ContentType /d text/plain /f");
            RunRegCommand(@"add HKCU\Software\Classes\.ps2\OpenWithProgids /v ps2_script /t REG_NONE /f");

            // 2. Configure ps2_script ProgID shell execution command
            RunRegCommand(@"add HKCU\Software\Classes\ps2_script /ve /d ""PS2 Script File"" /f");
            var shellCommand = $"\\\"{exePath}\\\" run \\\"%1\\\" %*";
            RunRegCommand($@"add HKCU\Software\Classes\ps2_script\shell\open\command /ve /d ""{shellCommand}"" /f");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[SUCCESS] .ps2 file association registered successfully!");
            Console.ResetColor();
            Console.WriteLine($"  Extension : .ps2");
            Console.WriteLine($"  ProgID    : ps2_script");
            Console.WriteLine($"  Command   : \"{exePath}\" run \"%1\" %*");
            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Failed to register registry association: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    public static bool UnregisterFileAssociation()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine("[INFO] Unregister is only applicable on Windows.");
            return false;
        }

        try
        {
            RunRegCommand(@"delete HKCU\Software\Classes\.ps2 /f");
            RunRegCommand(@"delete HKCU\Software\Classes\ps2_script /f");

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[SUCCESS] .ps2 file association removed from Windows registry.");
            Console.ResetColor();
            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Failed to unregister association: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }

    private static void RunRegCommand(string args)
    {
        var psi = new ProcessStartInfo("reg.exe", args)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var proc = Process.Start(psi);
        proc?.WaitForExit();
        if (proc != null && proc.ExitCode != 0)
        {
            var err = proc.StandardError.ReadToEnd();
            if (!string.IsNullOrWhiteSpace(err))
            {
                throw new InvalidOperationException($"reg.exe exited with code {proc.ExitCode}: {err.Trim()}");
            }
        }
    }
}
