rule Hex_Signature_Test
{
    meta:
        description = "Benchmark rule using hexadecimal string matching"
        author = "Research Benchmark"

    strings:
        // Common PE header bytes (MZ header)
        $hex1 = { 4D 5A 90 00 03 00 00 00 }
        // Common script marker bytes
        $hex2 = { 23 21 2F 75 73 72 2F 62 }
        // Common archive header bytes (PK zip)
        $hex3 = { 50 4B 03 04 }
        // Common PDF header bytes
        $hex4 = { 25 50 44 46 2D }

    condition:
        any of them
}
