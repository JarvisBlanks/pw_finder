#################################################################################
#                    CLEAR TEXT PASSWORD SCANNING                               #
#                                                                               #
#  This script attempts to access all specified file types on a computer files  #
#  Each file is then searched for potential password strings.                   #
#  The results are then encrypted and then moved to a remote file share.        #
#                                                                               #
#  Author: Alex Jarvis                                                          #
#                                                                               #
#  Changelog:                                                                   #
#  (AJ) v0.1 - 20210827 - Initial Version                                       #                          
#  (AJ) v1.0 - 20211231 - First Working vesion                                  #
#################################################################################

Function Write-Log ($Message)
{
    $Stamp = (Get-Date).toString("dd/MM/yy HH:mm:ss")
    $Line = "$Stamp $Message"
	Write-Host $Line
	$Line += "`n"
}

###### CONFIGURATION ############################################################
$Scope = ("*.txt", "*.xls", "*.doc","*.docx","*.xlsx","*.docm","*.xlsm","*.ps1", "*.py", "*.sh", "*.bat", "*.cmd", "*.cmdline", "*.vbs", "*.ini", "*.config", "*.conf", "*.xml", "*.aspx", "*.aspx", "*.js", "*.php", "*.pl", "*.cgi","*.json")
$pattern = "(?i)(?:^|\b)(password|pwd|passwd|pass|pswrd|p-word|pword)(\W|$)(.{1,30})"

write-log "Initializing..."

$global:passcount = 0
$count_doc = 0
$count_xls = 0
$count_ptf = 0
$skipcount = 0
$hostname = $env:computername
$filestr = "$((Get-Date).toString("yyyyMMdd"))_$($hostname)"
$localdest = "C:\temp\$($filestr).csv"
$encdest = "C:\temp\$($filestr).cms"
$remotedest = "\\X.X.X.X\pw_finder\"
$skip = @(
    "C:\Documents and Settings",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\Windows",
    "C:\ProgramData",
    "C:\System Volume Information",
    "C:\efi",
    "C:\Recovery",
    "C:\hp",
    "C:\Intel"
    )
$ignore = @(
    "*pw_finder_v1.0.ps1",
    "*\.vscode\*"
    )

$unique_pass = @(
    "password123",
    "password2022"
    )

$top_pass = @(
    "123456",
    "qwerty",
    "1q2w3e",
    "111111"
    )

#################################################################################

function Get_Info 
{    
    $csvheader = "File Name`tFile Hash`tPassword String"
    $csvheader | out-file -FilePath "$($localdest)"


    $folder = Get-ChildItem -path "C:\" -Directory -force -ErrorAction SilentlyContinue    
    $search = $folder.FullName | Where-Object {$skip -NotContains $_}

    write-log "Ready, Lets Gooo!"
    
    foreach($path in $search)
    {
        write-progress -id 0 -Activity "Scanning root directory:" -Status "$($path)"
        $Files = Get-ChildItem -path $path -recurse -include $scope -ErrorAction SilentlyContinue | Select-Object FullName
        $Files = $Files.FullName
        
        foreach($File in $Files)
        {
            write-progress -id 1 -Activity "Scanning File:" -Status "$($file)"
            
            foreach ($blah in $ignore){if($File -like $blah){$file = "skippy.skip"}}

            $hash = Get-FileHash $file -ErrorAction SilentlyContinue
            if(!$hash){$file = "skippy.skip"}

            Search_Filename $File

            $extn = [IO.Path]::GetExtension($File)

            if ($extn -eq ".skip")
            {
                $skipcount ++
            }
            elseif ($extn -eq ".docx" -or $extn -eq ".docx" -or $extn -eq ".docm")
            {
                $count_doc ++
                Search_Word $file
            }    
            elseif ($extn -eq ".xls" -or $extn -eq ".xlsx" -or $extn -eq ".xlsm")
            {
                $count_xls ++
                Search_Excel $file    
            } 
            else 
            {
                $count_ptf ++
                Search_Plaintext $file
                Search_common_passwords $file
            } 
        }
    }

    Write-Log "Finished scanning $($hostname)."
    Write-Host ""     
    Write-Host "---------------------------"  
    Write-Host "          Scanned"
    Write-Host "---------------------------"
    Write-Host " $($count_ptf)`tPlain Text Files."
    Write-Host " $($count_doc)`tDocuments."
    Write-Host " $($count_xls)`tSpreadsheets."
    Write-Host " $($skipcount)`tSkipped."
    Write-Host "---------------------------"

    
    if ($global:passcount -eq 0)
    {
        Write-Host " 0`tItems found!"
        Write-Host "---------------------------"
        Write-Host ""
        write-log "No items were found on $($hostname)! There is nothing to output."
        Remove-Item $localdest
    }
    else
    {
        Write-Host " $($global:passcount)`tItems found!"
        Write-Host "---------------------------"
        Write-Host ""
        
        encrypt 
        cleanup
    }
    Write-Log "Completely Finished, Finding The Nearest Exit..."
}

function Search_common_passwords
{
    try 
    {
        foreach($string in $unique_pass)
        {
            $ClearTextPwd = Select-String -path $File -Pattern "$($string)"
            $ClearTextPwd = $ClearTextPwd.Matches.Value
            
            if($ClearTextPwd)
            {
                foreach($pass in $ClearTextPwd)
                {
                    $csv = "$($File)`t$($Hash.hash)`t$($pass)"
                    $csv | Out-file -FilePath $localdest -Append
                    $global:passcount++
                }
            }   
        }
        foreach($string in $top_pass)
        {
            $ClearTextPwd = Select-String -path $File -Pattern "$($string)"
            $ClearTextPwd = $ClearTextPwd.Matches.Value
            
            if($ClearTextPwd)
            {
                foreach($pass in $ClearTextPwd)
                {
                    $csv = "$($File)`t$($Hash.hash)`t$($pass)"
                    $csv | Out-file -FilePath $localdest -Append
                    $global:passcount++
                }
            }   
        }
    }
    Catch
    {
        Write-Log "Error Accessing: $($File)"
    }
}
function Search_Plaintext
{
    try 
    {
        $ClearTextPwd = Select-String -path $File -Pattern "$($pattern)"
        $ClearTextPwd = $ClearTextPwd.Matches.Value
        
        if($ClearTextPwd)
        {
            foreach($pass in $ClearTextPwd)
            {
                $csv = "$($File)`t$($Hash.hash)`t$($pass)"
                $csv | Out-file -FilePath $localdest -Append
                $global:passcount++
            }
        }   
    }
    catch 
    {
        Write-Log "Error Accessing: $($File)"
    }
}

Function Search_Excel 
{
    try 
    {
        $fakepassword = "abcde"
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $False
        $excel.DisplayAlerts = $False
        $workbook = $excel.Workbooks.Open($file,0,$true,2,$fakepassword)
        ForEach ($Worksheet in @($Workbook.Sheets)) 
        {
            $Found = $WorkSheet.Cells.Find("pass")
            If ($Found) 
            {
                $BeginAddress = $Found.Address(0,0,1,1)   
                $ClearTextPwd = $found.text
                $ClearTextPwd = $ClearTextPwd -replace "`n",", " -replace "`r",", "
                $ClearTextPwd = $ClearTextPwd | Select-String -Pattern "(?i)(?:.{0,5}\b)(password|pwd|passwd|pass|pswrd|p-word|pword)(\b)(.{0,10})"
                $ClearTextPwd = $ClearTextPwd.Matches.Value       
                if($ClearTextPwd)
                {
                    $nxtcell = $($found.offset(0, +1).Text)
                    $nxtcell = $nxtcell -replace "`n",", " -replace "`r",", "
                    $nxtcell = $nxtcell | Select-String -Pattern "(?i)(.{0,15})"
                    $csv = "$($File)`t$($Hash.hash)($($Worksheet.Name))($($found.row),$($found.column))`t$($ClearTextPwd):$($nxtcell)"
                    $csv | Out-file -FilePath $localdest -Append
                    $global:passcount++
                }
                Do 
                {
                    $Found = $WorkSheet.Cells.FindNext($Found)
                    $Address = $Found.Address(0,0,1,1)
                    If ($Address -eq $BeginAddress) 
                    {
                        BREAK
                    }
                    $ClearTextPwd = $found.text
                    $ClearTextPwd = $ClearTextPwd -replace "`n",", " -replace "`r",", "
                    $ClearTextPwd = $ClearTextPwd | Select-String -Pattern "(?i)(?:.{0,5}\b)(password|pwd|passwd|pass|pswrd|p-word|pword)(\b)(.{0,10})"
                    $ClearTextPwd = $ClearTextPwd.Matches.Value       
                    if($ClearTextPwd)
                    {
                        $nxtcell = $($found.offset(0, +1).Text)
                        $nxtcell = $nxtcell -replace "`n",", " -replace "`r",", "
                        $nxtcell = $nxtcell | Select-String -Pattern "(?i)(.{0,15})"
                        $csv = "$($File)`t$($Hash.hash)($($Worksheet.Name))($($found.row),$($found.column))`t$($ClearTextPwd):$($nxtcell)"
                        $csv | Out-file -FilePath $localdest -Append
                        $global:passcount++
                    }   
                } Until ($False)
            }
        }
        $workbook.close($false)
        $Excel.Workbooks.close()
        $Excel.Application.Quit()
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$excel)
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()      
    }
    catch 
    {
        Write-Log "Error accessing: $($file)"
    } 
}
Function Search_Word
{
    try {
        Set-StrictMode -Version latest
        $application = New-Object -comobject word.application
        $application.visible = $False
        $document = $application.documents.open($file,$false,$true)
        $range = $document.content
        
        If($range.Text -match "$($pattern)")
        {
            $pass = $($Matches[0])
            $pass = $pass -replace "`t|`n|`r"," "
            $global:passcount++
            $csv = "$($File)`t$($Hash.hash)`t$pass"
            $csv | Out-file -FilePath $localdest -Append
            
        }

        $document.close()
        $application.quit()

    }
    catch 
    {
        Write-Log "Error accessing $($file)"
    } 
}

function Search_Filename
{
    try 
    {
        $ClearTextPwd = Select-String -InputObject $File -Pattern "$($pattern)"
        $ClearTextPwd = $ClearTextPwd.Matches.Value
            
        if($ClearTextPwd)
        {
            $csv = "$($File)`t$($Hash.hash)`t*Password String in File Name*"
            $csv | Out-file -FilePath $localdest -Append
            $global:passcount++
        }
    }
    catch 
    {
        Write-Log "Error accessing $($file)"
    } 
}
function cleanup
{
    Write-Log "Moving Encrypted File..."
    try 
    {
        if (Test-Path $($remotedest))
        {
            Write-Log "Connected to Remote Destination..."
        
            $files = Get-ChildItem  "C:\temp\*.cms"

            if ($files.count -gt 0)
            {            
                foreach ($file in $files)
                {
                    Write-Log "Moving $($file.name)"
                    Move-Item "$($file)" -Destination $remotedest -Force
                    if (Test-Path $file)
                    {
                        if (Test-Path "$($remotedest)\$($file.name)")
                        {
                            Remove-Item $($file)
                        }
                    }
                }
            }
        }   
    }
    catch 
    {
        Write-Log "Moving Failed! Remote Destination Unavailable."
    }
}

function encrypt
{
    Write-Log "Encrypting File..."
    $Cert=@'
    -----BEGIN NEW CERTIFICATE REQUEST-----

    -----END NEW CERTIFICATE REQUEST-----
'@

    $Cert | Out-File .\pw_finder.cer
    Protect-CmsMessage -To .\pw_finder.cer -Path $localdest -OutFile $encdest
    Remove-Item .\pw_finder.cer -Force
    Remove-Item $localdest -Force
}

Get_Info