import unittest
import xml.etree.ElementTree as ET

from localstorage import (
    NamecheapClient,
    build_domain_verification,
    build_required_namecheap_records,
    poll_namecheap_dns,
)


class NamecheapXmlParsingTests(unittest.TestCase):
    def test_list_dns_records_supports_lowercase_host_elements(self):
        xml_response = """
        <ApiResponse Status="OK">
          <CommandResponse Type="namecheap.domains.dns.getHosts">
            <DomainDNSGetHostsResult Domain="countrywater.online">
              <host HostId="1" Name="@" Type="A" Address="217.154.172.143" TTL="1800" />
              <host HostId="2" Name="_dmarc" Type="TXT" Address="v=DMARC1; p=none" TTL="1800" />
            </DomainDNSGetHostsResult>
          </CommandResponse>
        </ApiResponse>
        """

        client = NamecheapClient("api-user", "api-key", "username", "127.0.0.1")
        client._call = lambda command, extra_params=None: ET.fromstring(xml_response)  # type: ignore[method-assign]

        records = client.list_dns_records("countrywater.online")

        self.assertEqual(2, len(records))
        self.assertEqual("@", records[0]["name"])
        self.assertEqual("A", records[0]["type"])
        self.assertEqual("_dmarc", records[1]["name"])
        self.assertEqual("TXT", records[1]["type"])


class DomainVerificationTests(unittest.TestCase):
    def test_build_domain_verification_returns_snapshot_and_namecheap_matches(self):
        expected_ip = "217.154.172.143"
        domain = "countrywater.online"
        selector = "dkim"
        public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
        dmarc_value = "v=DMARC1; p=none; rua=mailto:dmarc@countrywater.online"
        spf_value = "v=spf1 ip4:217.154.172.143 ~all"
        expected_dkim = f"v=DKIM1; k=rsa; p={public_key}"

        original_builder = build_domain_verification.__globals__["build_namecheap_client"]
        original_resolver = build_domain_verification.__globals__["resolve_dns_values"]

        class StubClient:
            def list_dns_records(self, requested_domain):
                self_domain = requested_domain
                return [
                    {"name": "@", "type": "A", "address": expected_ip, "mx_pref": "", "ttl": "1800"},
                    {"name": "@", "type": "MX", "address": f"mail.{self_domain}", "mx_pref": "10", "ttl": "1800"},
                    {"name": "@", "type": "TXT", "address": spf_value, "mx_pref": "", "ttl": "1800"},
                    {"name": "_dmarc", "type": "TXT", "address": dmarc_value, "mx_pref": "", "ttl": "1800"},
                    {"name": f"{selector}._domainkey", "type": "TXT", "address": expected_dkim, "mx_pref": "", "ttl": "1800"},
                    {"name": "mail", "type": "A", "address": expected_ip, "mx_pref": "", "ttl": "1800"},
                ]

        def stub_builder(_config):
            return StubClient()

        def stub_resolver(name, record_type):
            if record_type == "A":
                return [expected_ip]
            if record_type == "MX":
                return [f"10 mail.{domain}"]
            if record_type == "TXT" and name == domain:
                return [spf_value]
            if record_type == "TXT" and name == f"{selector}._domainkey.{domain}":
                return [expected_dkim]
            if record_type == "TXT" and name == f"_dmarc.{domain}":
                return [dmarc_value]
            return []

        build_domain_verification.__globals__["build_namecheap_client"] = stub_builder
        build_domain_verification.__globals__["resolve_dns_values"] = stub_resolver
        try:
            result = build_domain_verification(
                {
                    "config": {},
                    "domain": domain,
                    "ipAddress": expected_ip,
                    "helo": f"mail.{domain}",
                    "selector": selector,
                    "spf": spf_value,
                    "dmarc": dmarc_value,
                    "publicKey": public_key,
                    "ttl": 1800,
                }
            )
        finally:
            build_domain_verification.__globals__["build_namecheap_client"] = original_builder
            build_domain_verification.__globals__["resolve_dns_values"] = original_resolver

        self.assertEqual("ok", result["overallStatus"])
        self.assertEqual(6, result["snapshot"]["count"])
        self.assertTrue(all(check["status"] == "ok" for check in result["checks"]))


class NamecheapPollingTests(unittest.TestCase):
    def test_build_required_namecheap_records_includes_mx_record(self):
        records = build_required_namecheap_records(
            {
                "domain": "countrywater.online",
                "ipAddress": "217.154.172.143",
                "selector": "dkim",
                "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
                "spf": "v=spf1 ip4:217.154.172.143 ~all",
                "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@countrywater.online",
                "ttl": 1800,
            }
        )

        self.assertIn(
            {"name": "@", "type": "MX", "address": "mail.countrywater.online", "mx_pref": "10", "ttl": "1800"},
            records,
        )

    def test_poll_namecheap_dns_sends_mx_record_to_namecheap(self):
        original_builder = poll_namecheap_dns.__globals__["build_namecheap_client"]
        captured = {}
        testcase = self

        class StubClient:
            def list_dns_records(self, requested_domain):
                testcase.assertEqual("countrywater.online", requested_domain)
                return [
                    {"name": "@", "type": "A", "address": "203.0.113.10", "mx_pref": "", "ttl": "1800"},
                ]

            def _set_hosts(self, domain, records):
                captured["domain"] = domain
                captured["records"] = records
                return True

        poll_namecheap_dns.__globals__["build_namecheap_client"] = lambda _config: StubClient()
        try:
            result = poll_namecheap_dns(
                {
                    "config": {},
                    "domain": "countrywater.online",
                    "ipAddress": "217.154.172.143",
                    "selector": "dkim",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
                    "spf": "v=spf1 ip4:217.154.172.143 ~all",
                    "dmarc": "v=DMARC1; p=none; rua=mailto:dmarc@countrywater.online",
                    "ttl": 1800,
                }
            )
        finally:
            poll_namecheap_dns.__globals__["build_namecheap_client"] = original_builder

        self.assertTrue(result["ok"])
        self.assertEqual("countrywater.online", captured["domain"])
        self.assertTrue(
            any(
                record["name"] == "@"
                and record["type"] == "MX"
                and record["address"] == "mail.countrywater.online"
                and record["mx_pref"] == "10"
                for record in captured["records"]
            )
        )


if __name__ == "__main__":
    unittest.main()
