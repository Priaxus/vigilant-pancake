import "pe"

rule ExampleRule
{
    meta:
        author = "Edwin Price"
        date = "17/11/2022"
        version = 0.1

    strings:
        $IOC_naughty_phrase_1 = "thisisbad"
        $IOC_naughty_hex_phrase = { E2 34 A1 C8 23 FB }

    condition:
        $IOC_naughty_phrase_1 at pe.entrypoint
}