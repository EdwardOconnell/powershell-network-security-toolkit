@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # These are interactive console tools: colored host output is the point.
        'PSAvoidUsingWriteHost'
    )
}
