import sys
import unittest
import datetime
import time
from sqlmodel import SQLModel, Session, create_engine, select

# Include system paths
from core.domain.scoring import (
    calculate_base_score,
    calculate_enrichment_score,
    calculate_time_decay,
    compute_final_risk_score
)
from workers.ingestion.parser import (
    identify_ioc_type,
    defang_value,
    parse_generic_json_feed,
    upsert_indicators
)
from api.auth import verify_api_key
from models.entities import Indicator, ThreatActor, Relationship

class TestScoringEngine(unittest.TestCase):
    def test_base_scoring(self):
        # file-sha256 weight is 1.0. Confidence is 80 -> Base score = 80
        score = calculate_base_score("file-sha256", 80)
        self.assertEqual(score, 80.0)
        
        # ipv4-addr weight is 0.6. Confidence is 100 -> Base score = 60
        score = calculate_base_score("ipv4-addr", 100)
        self.assertEqual(score, 60.0)

    def test_enrichment_scoring(self):
        # Test VirusTotal malicious detection ratios
        mock_enrichment = {
            "virustotal": {
                "last_analysis_stats": {
                    "harmless": 40,
                    "malicious": 10,
                    "suspicious": 0
                }
            }
        }
        score = calculate_enrichment_score(mock_enrichment)
        # 10 / 50 * 100 = 20.0
        self.assertEqual(score, 20.0)

        # Test Shodan vulnerability detections
        mock_shodan = {
            "shodan": {
                "vulns": ["CVE-2017-0144", "CVE-2021-44228"],
                "ports": [22, 443, 3389]
            }
        }
        score = calculate_enrichment_score(mock_shodan)
        # vulns: 2 * 20 = 40.0; critical ports: 3389 and 22 -> 2 * 10 = 20.0. Total = 60.0
        self.assertEqual(score, 60.0)

    def test_time_decay(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        # Seen right now -> No decay
        score = calculate_time_decay(100.0, now, decay_lambda=0.05)
        self.assertAlmostEqual(score, 100.0, places=2)
        
        # Seen 10 days ago -> 100 * e^(-0.05 * 10) = 100 * e^(-0.5) ~ 60.65
        past_date = now - datetime.timedelta(days=10)
        score = calculate_time_decay(100.0, past_date, decay_lambda=0.05)
        self.assertAlmostEqual(score, 60.65, places=2)

    def test_compute_final_risk_score(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        # Test combining base + enrichment + decay
        # ioc: ipv4-addr (weight 0.6)
        # confidence: 80 -> base_score = 48
        # enrichment: VT ratio 50% -> enrichment_score = 50
        # base_weight: 0.4, enrichment_weight: 0.6
        # initial = (48 * 0.4) + (50 * 0.6) = 19.2 + 30 = 49.2
        # decay: 0 days -> final = 49.2
        enrichment = {
            "virustotal": {
                "last_analysis_stats": {
                    "harmless": 10,
                    "malicious": 10,
                    "suspicious": 0
                }
            }
        }
        score = compute_final_risk_score("ipv4-addr", 80, now, enrichment)
        self.assertEqual(score, 49.2)


class TestParserAndDeduplication(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite DB engine for testing schema & inserts
        self.engine = create_engine("sqlite:///:memory:")
        SQLModel.metadata.create_all(self.engine)
        self.session = Session(self.engine)

    def tearDown(self):
        self.session.close()

    def test_ioc_identification(self):
        self.assertEqual(identify_ioc_type("192.168.1.100"), "ipv4-addr")
        self.assertEqual(identify_ioc_type("badactor.xyz"), "domain-name")
        self.assertEqual(identify_ioc_type("https://malicious-domain.com/path?id=12"), "url")
        self.assertEqual(identify_ioc_type("a" * 64), "file-sha256")
        self.assertEqual(identify_ioc_type("b" * 32), "file-md5")
        self.assertEqual(identify_ioc_type("invalid_indicator"), "unknown")

    def test_defanging(self):
        self.assertEqual(defang_value("ipv4-addr", "8.8.8.8"), "8.8.8[.]8")
        self.assertEqual(defang_value("domain-name", "phishing.com"), "phishing[.]com")
        self.assertEqual(defang_value("url", "http://malicious.net/exec.exe"), "hxxp://malicious[.]net/exec.exe")
        self.assertEqual(defang_value("file-sha256", "abc"), "abc")  # Hash remains untouched

    def test_db_upsert_deduplication(self):
        # 1. First ingestion of an IP
        feed = [
            {"value": "198.51.100.1", "confidence": 70, "labels": ["malware"]}
        ]
        upsert_indicators(self.session, feed, "OSINT-Feed-A")
        
        # Verify it got inserted
        results = self.session.exec(select(Indicator)).all()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].value, "198.51.100.1")
        self.assertEqual(results[0].confidence, 70)
        self.assertEqual(results[0].custom_properties["reporting_sources"], ["OSINT-Feed-A"])
        
        # 2. Second ingestion of the exact same IP from a different source
        time.sleep(0.1)  # tiny sleep to test modifier logic
        feed_duplicate = [
            {"value": "198.51.100.1", "confidence": 50, "labels": ["apt"]}
        ]
        upsert_indicators(self.session, feed_duplicate, "OSINT-Feed-B")
        
        # Verify that we still have only 1 row in the table (DEDUPLICATION)
        results_after = self.session.exec(select(Indicator)).all()
        self.assertEqual(len(results_after), 1)
        # Confidence should increase slightly due to multi-source verification (+5 rule)
        self.assertEqual(results_after[0].confidence, 75)
        # Custom property reporting_sources should contain both feeds
        self.assertIn("OSINT-Feed-A", results_after[0].custom_properties["reporting_sources"])
        self.assertIn("OSINT-Feed-B", results_after[0].custom_properties["reporting_sources"])


class TestAuthentication(unittest.TestCase):
    def test_verify_api_key(self):
        # Test valid admin keys
        role = verify_api_key("admin-secret-key-12345")
        self.assertEqual(role, "Admin")
        
        # Test valid analyst keys
        role = verify_api_key("analyst-secret-key-67890")
        self.assertEqual(role, "Analyst")
        
        # Test invalid key raises 401
        with self.assertRaises(Exception):
            verify_api_key("invalid-key")


if __name__ == "__main__":
    unittest.main()
