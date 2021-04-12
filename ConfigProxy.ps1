<#	
  .Synopsis
    Configures device level PROXY + exceptions to assist with OOBE enrolments etc
  .NOTES
    Created:   	    April, 2021
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       ConfigProxy.ps1
  .DESCRIPTION
    common scenarios set
    1. Auto Detect + ProxyServer:Port + ExceptionURLs + don't use proxy for local intranet addresses
	2. Auto Detect + ProxyServer:Port + don't use proxy for local intranet addresses
    3. Auto Detect + Autoconfig URL

    Automatically detect settings always On
    Don't use the proxy server for local (intranet) addresses selected when using proxy server

  .REFERENCES
    http://learningpcs.blogspot.com/2009/07/powershell-string-to-hex-or-whatever.html
    https://www.powershellgallery.com/packages/Utility.PS/1.0.0.1/Content/ConvertTo-HexString.ps1

  .EXAMPLE
    
    1. Configure Proxy Server & Port with URL Exceptions (must be delimited by semi-colons)
    powershell.exe -ep bypass -file .\ConfigProxy.ps1 -ProxyServer ProxyServer -ProxyPort ProxyPort -ExceptionURL ExceptionURL;ExceptionURL;ExceptionURL

    2. Configure Proxy Server & Port
    powershell.exe -ep bypass -file .\ConfigProxy.ps1 -ProxyServer ProxyServer -ProxyPort ProxyPort

    3. Configure Proxy AutoConfigure Script (.PAC)
    powershell.exe -ep bypass -file .\ConfigProxy.ps1 -ProxyURL ProxyURL
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$ProxyURL=$script:ProxyURL,
    [Parameter(Mandatory=$false)]
    [string]$ProxyServer=$script:ProxyServer,
    [Parameter(Mandatory=$false)]
    [string]$ProxyPort=$script:ProxyPort,
    [Parameter(Mandatory=$false)]
    [string]$ExceptionURLs=$script:ExceptionURLs
)
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
}

<#
    .SYNOPSIS
    Convert to Hex String
    .DESCRIPTION
    https://www.powershellgallery.com/packages/Utility.PS/1.0.0.1/Content/ConvertTo-HexString.ps1
    .EXAMPLE
        PS C:\>ConvertTo-HexString "What is a hex string?"
        Convert string to hex byte string seperated by spaces.
    .EXAMPLE
        PS C:\>"ASCII string to hex string" | ConvertTo-HexString -Delimiter "" -Encoding Ascii
        Convert ASCII string to hex byte string with no seperation.
    .INPUTS
        System.Object
#>
function ConvertTo-HexString {
    [CmdletBinding()]
    param (
        # Value to convert
        [Parameter(Mandatory=$true, Position = 0, ValueFromPipeline=$true)]
        [object] $InputObjects,
        # Delimiter between Hex pairs
        [Parameter (Mandatory=$false)]
        [string] $Delimiter = ' ',
        # Encoding to use for text strings
        [Parameter (Mandatory=$false)]
        [ValidateSet('Ascii', 'UTF32', 'UTF7', 'UTF8', 'BigEndianUnicode', 'Unicode')]
        [string] $Encoding = 'Default'
    )

    begin {
        function Transform ([byte[]]$InputBytes) {
            [string[]] $outHexString = New-Object string[] $InputBytes.Count
            for ($iByte = 0; $iByte -lt $InputBytes.Count; $iByte++) {
                $outHexString[$iByte] = $InputBytes[$iByte].ToString('X2')
            }
            return $outHexString -join $Delimiter
        }

        ## Create list to capture byte stream from piped input.
        [System.Collections.Generic.List[byte]] $listBytes = New-Object System.Collections.Generic.List[byte]
    }

    process
    {
        if ($InputObjects -is [byte[]])
        {
            Write-Output (Transform $InputObjects)
        }
        else {
            foreach ($InputObject in $InputObjects) {
                [byte[]] $InputBytes = $null
                if ($InputObject -is [byte]) {
                    ## Populate list with byte stream from piped input.
                    if ($listBytes.Count -eq 0) {
                        Write-Verbose 'Creating byte array from byte stream.'
                        Write-Warning ('For better performance when piping a single byte array, use "Write-Output $byteArray -NoEnumerate | {0}".' -f $MyInvocation.MyCommand)
                    }
                    $listBytes.Add($InputObject)
                }
                elseif ($InputObject -is [byte[]])
                {
                    $InputBytes = $InputObject
                }
                elseif ($InputObject -is [string])
                {
                    $InputBytes = [Text.Encoding]::$Encoding.GetBytes($InputObject)
                }
                elseif ($InputObject -is [bool] -or $InputObject -is [char] -or $InputObject -is [single] -or $InputObject -is [double] -or $InputObject -is [int16] -or $InputObject -is [int32] -or $InputObject -is [int64] -or $InputObject -is [uint16] -or $InputObject -is [uint32] -or $InputObject -is [uint64])
                {
                    $InputBytes = [System.BitConverter]::GetBytes($InputObject)
                }
                elseif ($InputObject -is [guid])
                {
                    $InputBytes = $InputObject.ToByteArray()
                }
                elseif ($InputObject -is [System.IO.FileSystemInfo])
                {
                    if ($PSVersionTable.PSVersion -ge [version]'6.0') {
                        $InputBytes = Get-Content $InputObject.FullName -Raw -AsByteStream
                    }
                    else {
                        $InputBytes = Get-Content $InputObject.FullName -Raw -Encoding Byte
                    }
                }
                else
                {
                    ## Non-Terminating Error
                    $Exception = New-Object ArgumentException -ArgumentList ('Cannot convert input of type {0} to Hex string.' -f $InputObject.GetType())
                    Write-Error -Exception $Exception -Category ([System.Management.Automation.ErrorCategory]::ParserError) -CategoryActivity $MyInvocation.MyCommand -ErrorId 'ConvertHexFailureTypeNotSupported' -TargetObject $InputObject
                }

                if ($null -ne $InputBytes -and $InputBytes.Count -gt 0) {
                    Write-Output (Transform $InputBytes)
                }
            }
        }
    }

    end {
        ## Output captured byte stream from piped input.
        if ($listBytes.Count -gt 0) {
            Write-Output (Transform $listBytes.ToArray())
        }
    }
}

<# function string2hex {
    param (
        [string]$string
    )
    $c = ''
    $d = ''
    $hexarray = ''
    $array = $string.Split(' ')
    #convert each string element into Hex Bytes
    Foreach ($element in $array) {
        $c = $c + " " + [System.String]::Format("{0:X2}", [System.Convert]::ToUInt32($element))
    }
    #turn into array after trimming
    $d = $c.TrimStart()
    $hexarray = $d.Split(' ') | % {"0x$_"}
    return $hexarray
} #>

#Main
if ($script:ProxyServer) {
    #if ([string]::IsNullOrEmpty($script:ProxyPort)){
    if ($script:ProxyPort){
        $proxyname = "$script:ProxyServer" + ":" + "$script:ProxyPort"
    } else {
        $proxyname = "$script:ProxyServer"
    }
    if ($script:ExceptionURLs) {
        #Always 46 and zeros for first byte. 0B is Manual proxy with Auto Detect. 14 is 
        $Data1 = "46 00 00 00 00 00 00 00 0B 00 00 00"
        $Data2 = ConvertTo-HexString $proxyname.length
        #$Data3 = "00 00 00" #added to Data2
        $Data4 = ConvertTo-HexString "$proxyname"
        $Data5 = ConvertTo-HexString ($script:ExceptionURLs.length + 8) #Data8
        #$Data6 = "00 00 00" #added to Data5
        $Data7 = ConvertTo-HexString "$script:ExceptionURLs"
        #Always assume "don't use proxy for local intranet addresses" ticked
        $Data8 = "3B 3C 6C 6F 63 61 6C 3E"
        $Data9 = "00 00 00 00"
        $Data10 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        $hexarray = $Data1 + " " + $Data2 + " " + $Data4 + " " + $Data5 + " " + $Data7 + " " + $Data8 + " " + $Data9 + " " + $Data10
        #$hexarray = $Data1 + " " + $Data2 + " " + $Data3 + " " + $Data4 + " " + $Data5 + " " + $Data6 + " " + $Data7 + " " + $Data8 + " " + $Data9 + " " + $Data10
    } else {
        #No Exception URLs
        #Always 46 and zeros for first byte. 0B is Manual proxy with Auto Detect. 14 is 
        $Data1 = "46 00 00 00 00 00 00 00 0B 00 00 00"
        $Data2 = ConvertTo-HexString $proxyname.length
        #$Data3 = "00 00 00" #added to Data2
        $Data4 = ConvertTo-HexString "$proxyname"
        $Data5 = ConvertTo-HexString 8 #Data7
        #$Data6 = "00 00 00" #added to Data5
        #Always assume "don't use proxy for local intranet addresses" ticked
        $Data7 = "3C 6C 6F 63 61 6C 3E"
        $Data8 = "00 00 00 00"
        $Data9 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        $Data10 = ""
        $hexarray = $Data1 + " " + $Data2 + " " + $Data4 + " " + $Data5 + " " + $Data7 + " " + $Data8 + " " + $Data9
        #$hexarray = $Data1 + " " + $Data2 + " " + $Data3 + " " + $Data4 + " " + $Data5 + " " + $Data6 + " " + $Data7 + " " + $Data8 + " " + $Data9
    }
}

if ($script:ProxyURL) {
    #Always 46 and zeros for first byte. 0D is Manual proxy with Auto Detect. 14 is 
        $Data1 = "46 00 00 00 01 00 00 00 0D 00 00 00 00 00 00 00"
        $Data2 = "00 00 00 00"
        $Data3 = ConvertTo-HexString $script:ProxyURL.length
        $Data4 = "00 00 00"
        $Data5 = ConvertTo-HexString "$script:ProxyURL"
        $Data6 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        $Data7 = ""
        $Data8 = ""
        $Data9 = ""
        $Data10 = ""
        $hexarray = $Data1 + " " + $Data2 + " " + $Data3 + " " + $Data4 + " " + $Data5 + " " + $Data6
}

$DefaultConnectionSettings = $hexarray.Split(' ') | % {"0x$_"}

write-host $DefaultConnectionSettings
#write to registry as binary -value ([byte][]]$DefaultConnectionSettings)
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name "DefaultConnectionSettings" -Type Binary -Value ([byte[]]$DefaultConnectionSettings) -ErrorAction SilentlyContinue -Force

