rule Text_Signature_Test
{
    meta:
        description = "Benchmark rule using plain text string matching"
        author = "Research Benchmark"

    strings:
        // Common plaintext markers found in scripts/configs
        $text1 = "#!/usr/bin/python" nocase
        $text2 = "#!/bin/bash" nocase
        $text3 = "import socket" nocase
        $text4 = "CreateRemoteThread" nocase

    condition:
        any of them
}
