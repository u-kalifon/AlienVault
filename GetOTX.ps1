# Get the new indicators from AlienVault and add to our indicators files

$otxkey = "1c60b9eb0c5f39a4edbe46d90009b38aacaf4830512e9e37e6598aa96a1e03ca"

[String[]]$Hostnames = @()
[String[]]$IPV4s = @()
[String[]]$IPV6s = @()
[String[]]$URLs = @()
[String[]]$Hashes = @()
[String[]]$Emails = @()
[String[]]$IDs = @()

# get the last indicators 
$LatestHostname = (Get-Content "hostnames.txt" -First 100).trim()
$LatestIpv4 = (Get-Content "ipv4s.txt" -First 100).trim()
$LatestIpv6 = (Get-Content "ipv6s.txt" -First 100).trim()
$LatestUrl = (Get-Content "urls.txt" -First 100).trim()
$LatestHash = (Get-Content "hashes.csv" -First 100).trim()
$LatestEmail = (Get-Content "emails.txt" -First 100).trim()
$LatestID = (Get-Content "ids.txt" -First 100).trim()

$stop = $false
for ($page = 1; $page -le 30 -and -not $stop; $page ++) {
	$url = "https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=10&page=$page"
	Write-Host "Getting: $url" -foregroundcolor "Yellow"
	$indicators = invoke-webrequest -URI $url -UseBasicParsing -Headers @{"X-OTX-API-KEY"="$otxkey"} -UseDefaultCredentials

	# Convert JSON data received into powershell object.
	$data = $indicators.Content | ConvertFrom-Json

	foreach ($item in $data.results){
		# Store the id of the intelligence item
		$id = $item.id.trim()
		if ( $LatestID.Contains($id) ) {
			$stop = $true
			break
		}
		$IDs += $id + "`n"

		foreach ($indicator in $Item.Indicators) {
			# sanitize the indicator
			$indicator_value = $indicator.Indicator.trim()

			# Gather Domain and Subdomain Names Indicators
			if ($indicator.Type -eq "hostname" -or $indicator.type -eq "domain"){
				if ( -Not $LatestHostname.Contains($indicator_value) ) {
					$Hostnames += $indicator_value + "`n"
				} else {
					Write-Host "Indicator $indicator_value already exists in the database" -foregroundcolor "Green"
				}
			}
			# Gather All IPV4 Indicators
			if ($indicator.Type -eq "IPv4"){
				if ( -Not $LatestIpv4.Contains($indicator_value) ) {
					$IPV4s += $indicator_value + "`n"
				} else {
					Write-Host "Indicator $indicator_value already exists in the database" -foregroundcolor "Green"
				}
			}
			# Gather All IPV6 Indicators
			if ($indicator.Type -eq "IPv6"){
				if ( -Not $LatestIpv6.Contains($indicator_value) ) {
					$IPV6s += $indicator_value + "`n"
				} else {
					Write-Host "Indicator $indicator_value already exists in the database" -foregroundcolor "Green"
				}
			}
			# Gather All URL Indicators
			if ($indicator.Type -eq "URL" -and $indicator_value){
				if ( -Not $LatestUrl.Contains($indicator_value) ) {
					$URLs += $indicator_value + "`n"
				} else {
					Write-Host "Indicator $indicator_value already exists in the database" -foregroundcolor "Green"
				}
			}
			# Gather all File Hash Indicators
			if ($indicator.Type -eq "FileHash-MD5" -or $indicator.Type -eq "FileHash-SHA1" -or $indicator.Type -eq "Filehash-SHA256"){
				$indicator_type = ""
				if ($indicator.Type -eq "FileHash-MD5") {$indicator_type = "FileMD5"}		# for Defender
				if ($indicator.Type -eq "FileHash-SHA1") {$indicator_type = "FileSha1"}		# for Defender
				if ($indicator.Type -eq "Filehash-SHA256") {$indicator_type = "FileSha256"}	# for Defender

				$CsvIndicator = "$indicator_type,$indicator_value,,Warn,Informational,`"AlienVault Indicator Detected`",`"Possible infection, please notify IT`",,,,,true"

				if ( -Not $LatestHash.Contains($CsvIndicator) ) {
					$Hashes += $CsvIndicator + "`n"
				} else {
					Write-Host "Indicator $indicator_value already exists in the database" -foregroundcolor "Green"
				}
			}
			# Gather all Email Indicators
			if ($indicator.Type -eq "email"){
				if ( -Not $LatestEmail.Contains($indicator_value) ) {
					$Emails += $indicator_value + "`n"
				} else {
					Write-Host "Indicator $indicator_value already exists in the database" -foregroundcolor "Green"
				}
			}
		}
	}
	if ($data.next -eq $null) {break}
}

Function Combine-Data {
	param (
		$DataArray,
		$FileName
	)

	$DataArray.trim() | Set-Content "$FileName.temp"
	Add-Content -Path "$FileName.temp" -Value (Get-Content $FileName -First 10000)
	Copy-Item "$FileName.temp" -Destination $FileName
}

if ($URLs.count -gt 0) {Combine-Data $URLs "urls.txt"}
if ($Hostnames.count -gt 0) {Combine-Data $Hostnames "hostnames.txt"}
if ($IPV4s.count -gt 0) {Combine-Data $IPV4s "ipv4s.txt"}
if ($IPV6s.count -gt 0) {Combine-Data $IPV6s "ipv6s.txt"}
if ($Hashes.count -gt 0) {Combine-Data $Hashes "hashes.csv"}
if ($Emails.count -gt 0) {Combine-Data $Emails "emails.txt"}
if ($IDs.count -gt 0) {Combine-Data $IDs "ids.txt"}

write-host "Finished" -foregroundcolor "green"
