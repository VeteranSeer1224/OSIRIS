from sense_clean import generate_raw_scan


def test_unknown_entities_preserved():
    raw = [
        {
            "type": "CUSTOM_ENTITY",
            "data": "abc123",
            "module": "sfp_custom"
        },
        {
            "type": "DOMAIN_NAME",
            "data": "example.com",
            "module": "sfp_dns"
        }
    ]

    scan = generate_raw_scan(
        "example.com",
        raw
    )

    assert len(
        scan["raw_module_output"]["unknown_entities"]
    ) == 1


def test_dns_record_normalization():
    raw = [
        {
            "type": "DNS_MX",
            "data": "mail.example.com",
            "module": "sfp_dns"
        }
    ]

    scan = generate_raw_scan(
        "example.com",
        raw
    )

    assert scan["entities"][0]["type"] == "dns_record"


def test_asn_normalization():
    raw = [
        {
            "type": "BGP_AS",
            "data": "AS15169",
            "module": "sfp_bgp"
        }
    ]

    scan = generate_raw_scan(
        "example.com",
        raw
    )

    assert scan["entities"][0]["type"] == "asn"


def test_certificate_normalization():
    raw = [
        {
            "type": "SSL_CERTIFICATE_RAW",
            "data": "cert-data",
            "module": "sfp_ssl"
        }
    ]

    scan = generate_raw_scan(
        "example.com",
        raw
    )

    assert scan["entities"][0]["type"] == "certificate"


def test_raw_export_preserved():
    raw = [
        {
            "type": "DNS_A",
            "data": "1.1.1.1"
        }
    ]

    scan = generate_raw_scan(
        "example.com",
        raw
    )

    assert scan["raw_module_output"]["records"] == raw