$in = 'C:\Users\kilia\Downloads\VulReport-main\VulReport-main\.tmp_docx_extract\word\document.xml'
$out = 'C:\Users\kilia\Downloads\VulReport-main\VulReport-main\.tmp_docx_text.txt'

$xml = Get-Content -Raw $in
$xml = $xml -replace '</w:p>',"`n"
$xml = $xml -replace '<w:tab/>',"`t"
$xml = $xml -replace '<w:br\s*/>',"`n"
$xml = $xml -replace '<[^>]+>',''
$xml = [System.Net.WebUtility]::HtmlDecode($xml)

$xml | Set-Content -Encoding UTF8 $out
