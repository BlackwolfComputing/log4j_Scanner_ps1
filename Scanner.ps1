

$Drives = "C:\","D:\" #Can be replaced with attached File storage/sharedrives
$log = '.\' #Operational catalog hash.txt needs to be placed here
$hostname = Hostname #Will be name of Results file

function AddToObject ($obj, $PropName, $Val) {
$obj | Add-Member -MemberType NoteProperty -Name $PropName -Value $Val -Force
}

function Entry($Vpath,$vtype,$version){
$properties = @{
Time         = Get-Date -Format "yyyy-MM-dd_hh:mm:ss"
VulnFilePath = $VPath
VulnType     = $Vtype
Version      = $version

}
return $(New-Object -TypeName psobject -Property $properties)
}

$FindingsTab = @()


#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
$hostname = Hostname

$vulnerablelist = $(Get-Content "$log\hash.txt")
$localsums = $null

$VulnerableFiles = ((-Split $vulnerablelist |? {$_.length -ne 64})|%{$_.Replace('./','')}).Split('/')
    foreach ($drive in $Drives){
     #$example = (ls 'V:\US\I-net_arkitektur\Graf komponent\2.0\jakarta-tomcat\webapps').FullName
     $ScanFiles = get-childitem -path "$drive" -Recurse | ?{$_.Extension -in ".jar",".war",".ear"} -ErrorAction SilentlyContinue | Get-FileHash
        foreach ($file in $ScanFiles) {

        if ($file.Path -like "*log4j-core*.jar"){ #LOG4J-CORE USED
            $Test = $((Compare-Object $LH.Hash -DifferenceObject $vulnerablesums -IncludeEqual -ErrorAction SilentlyContinue).SideIndicator -eq "==")
            if ( $Test -eq "==" ) {
            $Vuln = ($vulnerablelist -like "*$($LH.Hash)*")
            AddToObject $LH 'Vulnerable' 'True'
            AddToObject $LH 'Version' "$($Vuln.Replace($lh.Hash,''))"
            $FindingsTab += Entry $lh.Path "JAR-Vulnerable" $lh.Version
            }
        } else { #OTHER FILE TYPES


        $EXT = "$(($file.Path).Split('\')[-1].Split('.')[-1])"
        $filelist = jar tvf $file.Path
        
        foreach ($entr in $filelist){
        
        $en= (($entr.Trim()).Split('')[-1]).Split('/')[-1]
        #Read-Host
         if (!($en -eq $null)) {
            if ($(Compare-Object $VulnerableFiles -DifferenceObject $en -IncludeEqual -ExcludeDifferent).SideIndicator -eq '==')
                    {
                    $time = Get-Date -Format "yyyy-MM-dd_hh:mm:ss"
                    $FindingsTab += Entry $File.Path "$EXT : Vulnerable" $entr
                        } else 
                            {#Compare only names
                            if ($en -like "*Log4j*"){
                            $time = Get-Date -Format "yyyy-MM-dd_hh:mm:ss"
                            $file.Path
                            $entr
                            $FindingsTab += Entry $File.Path "$EXT :Log4J Used" $entr
                            }
                        }
         } #NOT NULL
            }
          }
     } #FOREACh FILE
}

if ($FindingsTab.count -eq 0){"No Vulnerabilities found" | Out-File "$log\$hostname WAR.log"}
else {
$FindingsTab | Export-Csv -Path "$log\$hostname WAR.log" -NoTypeInformation -Force
}
$Error |Select Exception | Export-Csv -Path "$log\$hostname WAR-Errors.csv"  -NoTypeInformation -Force
