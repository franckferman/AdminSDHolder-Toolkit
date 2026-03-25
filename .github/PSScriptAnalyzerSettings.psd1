@{
    ExcludeRules = @(
        # Interactive CLI scripts — Write-Host with -ForegroundColor is intentional
        'PSAvoidUsingWriteHost',

        # UTF-8 without BOM is intentional for cross-platform compatibility
        'PSUseBOMForUnicodeEncodedFile'
    )
}
