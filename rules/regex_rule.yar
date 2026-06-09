rule Regex_Signature_Test
{
    meta:
        description = "Benchmark rule using regular expression string matching"
        author = "Research Benchmark"

    strings:
        // Regex matching PE header pattern
        $re1 = /MZ.{0,120}PE\x00\x00/ nocase
        // Regex matching common script shebang patterns
        $re2 = /^#!(\/usr\/bin\/|\/bin\/)(python|bash|sh|perl)[^\n]*/
        // Regex matching IP address patterns (common in malware C2 configs)
        $re3 = /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\b/
        // Regex matching URL patterns
        $re4 = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/

    condition:
        any of them
}
