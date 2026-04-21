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





rule High_Entropy_Executable {
    meta:
        description = "Exécutable potentiellement packé ou choffré"
        severity    = "medium"
    strings:
        $mz_header = { 4D 5A }  // Signature MZ de tout exécutable Windows
        
    condition:
        $mz_header at 0 and filesize > 1KB
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
        any of them
}
