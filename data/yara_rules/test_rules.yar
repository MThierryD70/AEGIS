
rule EICAR_Test_File {
    meta:
        description = "Détecte le fichier de test EICAR standard"
        severity    = "critical"
        author      = "Test"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}

rule Packed_Executable_UPX {
    meta:
        description = "Exécutable Windows packé avec UPX (heuristique packer)"
        severity    = "medium"
    strings:
        $mz  = { 4D 5A }            // Signature MZ de tout exécutable Windows
        $upx0 = "UPX0" ascii        // Section 0 des binaires packés UPX
        $upx1 = "UPX1" ascii        // Section 1 des binaires packés UPX
    condition:
        $mz at 0 and filesize > 1KB and $upx0 and $upx1
}

rule Suspicious_Script {
    meta:
        description = "Script avec pattern d'obfuscation"
        severity    = "medium"
    strings:
        $eval_b64  = "eval(base64_decode)" ascii nocase
        $eval_gzip = "eval(gzinflate)" ascii nocase
        $fromchar  = "fromCharCode" ascii
    condition:
        2 of them
}
