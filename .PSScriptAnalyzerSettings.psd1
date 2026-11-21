@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Interactive CLI and standalone test runner scripts intentionally emit console status via Write-Host.
        'PSAvoidUsingWriteHost'
        # Several helper functions and test assertions intentionally use natural names (e.g. Enable-ModernTls, Assert-Throws).
        'PSUseSingularNouns'
    )
}
