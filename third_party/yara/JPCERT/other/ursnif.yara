rule malware_Ursnif_strings {
          meta:
            description = "detect Ursnif(a.k.a. Dreambot, Gozi, ISFB) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"




          strings:
            $a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
            $b1 = "client.dll" fullword
            $c1 = "version=%u"
            $c2 = "user=%08x%08x%08x%08x"
            $c3 = "server=%u"
            $c4 = "id=%u"
            $c5 = "crc=%u"
            $c6 = "guid=%08x%08x%08x%08x"
            $c7 = "name=%s"
            $c8 = "soft=%u"
            $d1 = "%s://%s%s"
            $d2 = "PRI \x2A HTTP/2.0"
            $e1 = { A1 ?? ?? ?? 00 35 E7 F7 8A 40 50 }
            $e2 = { 56 56 56 6A 06 5? FF ?? ?? ?? ?? 00 }
            $f1 = { 56 57 BE ?? ?? ?? ?? 8D ?? ?? A5 A5 A5 }
            $f2 = { 35 8F E3 B7 3F }
            $f3 = { 35 0A 60 2E 51 }

          condition:
            $a1 or ($b1 and 3 of ($c*)) or (5 of ($c*)) or ($b1 and all of ($d*)) or all of ($e*) or all of ($f*)
}
