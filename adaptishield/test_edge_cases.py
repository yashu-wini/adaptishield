#!/usr/bin/env python3
"""
Edge Case Test Suite for AdaptiShield
======================================
Tests false positive rejection AND true positive detection.
Run: python test_edge_cases.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pipeline import AdaptiShieldPipeline

# Initialize pipeline WITHOUT transformer (fast, deterministic tests)
print("🛡️  Initializing pipeline for edge case testing...")
pipeline = AdaptiShieldPipeline(
    use_transformer=False,
    use_spacy=False,
    use_context_verifier=False,  # Test without NLI verifier (deterministic)
    encrypt_output=False,
    log_results=False
)

def get_validated_types(result):
    """Get entity types that survived validation (not rejected/ignored)."""
    return {
        e["entity_type"] for e in result["entities"]
        if e.get("sensitivity_level") not in (None, "IGNORED")
        and e.get("confidence", 0) >= 0.25
    }

test_results = []

def run_test(test_id, description, text, should_detect=None, should_reject=None,
             check_anonymized_contains=None):
    """Run a single test case."""
    result = pipeline.process_text(text)
    validated = get_validated_types(result)
    passed = True
    
    print(f"\n─── {test_id}: {description} ───")
    print(f"  Input: \"{text[:80]}{'...' if len(text)>80 else ''}\"")
    print(f"  Detected (validated): {validated or '{none}'}")
    
    if result.get("anonymized_text"):
        print(f"  Anonymized: \"{result['anonymized_text'][:80]}{'...' if len(result['anonymized_text'])>80 else ''}\"")
    
    if should_detect:
        for entity_type in should_detect:
            if entity_type in validated:
                print(f"  ✅ PASS Correctly detected: {entity_type}")
            else:
                print(f"  ❌ FAIL Expected detection: {entity_type}")
                passed = False
    
    if should_reject:
        for entity_type in should_reject:
            if entity_type not in validated:
                print(f"  ✅ PASS Correctly rejected: {entity_type}")
            else:
                print(f"  ❌ FAIL Should have rejected: {entity_type}")
                passed = False
    
    if check_anonymized_contains:
        anon = result.get("anonymized_text", "")
        if check_anonymized_contains in anon:
            print(f"  ✅ PASS Anonymized text contains: \"{check_anonymized_contains}\"")
        else:
            print(f"  ❌ FAIL Anonymized should contain: \"{check_anonymized_contains}\"")
            passed = False
    
    test_results.append((test_id, description, passed))
    return result


print("\n" + "="*60)
print("USER-REPORTED EDGE CASES")
print("="*60)

# ── Following-word analysis (NEW) ──
run_test("FW-1",
    "'7000138006 followers' should NOT be phone",
    "I have reached 7000138006 followers, please reach out to me",
    should_reject=["PHONE"])

run_test("FW-2",
    "'9876543210 users' should NOT be phone",
    "Our platform now serves 9876543210 users worldwide.",
    should_reject=["PHONE"])

run_test("FW-3",
    "'9876543210 downloads' should NOT be phone",
    "The app has crossed 9876543210 downloads this year.",
    should_reject=["PHONE"])

run_test("FW-4",
    "Real phone with context SHOULD be detected",
    "Call me at 9876543210 for the meeting.",
    should_detect=["PHONE"])

# ── Preceding label analysis ──
run_test("USER-1",
    "'ABCDE1234F' in prose should NOT be PAN",
    "The ABCDE1234F algorithm was tested and found efficient.",
    should_reject=["PAN"])

run_test("USER-1b",
    "Real PAN with tax context SHOULD be detected",
    "PAN Card: ABCDE1234F | Income Tax Return filed.",
    should_detect=["PAN"])

run_test("USER-2",
    "'Python 3.9876543210' should NOT detect phone",
    "Python 3.9876543210",
    should_reject=["PHONE"])

run_test("USER-3a",
    "'password policy:' should NOT be detected as password",
    "password policy: minimum 8 characters",
    should_reject=["PASSWORD"],
    check_anonymized_contains="password policy: minimum 8 characters")

run_test("USER-3b",
    "'Reset your password: click here' should NOT be password",
    "Reset your password: click here",
    should_reject=["PASSWORD"],
    check_anonymized_contains="Reset your password: click here")

run_test("USER-3c",
    "Real password SHOULD be detected",
    "My password: Secret@123!",
    should_detect=["PASSWORD"])

run_test("USER-4",
    "'My account number is 12345678901234' SHOULD detect bank account",
    "My account number is 12345678901234",
    should_detect=["BANK_ACCOUNT"])

print("\n" + "="*60)
print("PREVIOUS EDGE CASES (REGRESSION CHECK)")
print("="*60)

run_test("EC-1",
    "Tracking number (valid Luhn) should NOT be credit card",
    "Tracking: 4532015112830366",
    should_reject=["CREDIT_CARD"])

run_test("EC-1b",
    "Real credit card with 'Card:' label SHOULD be detected",
    "Credit Card: 4532015112830366",
    should_detect=["CREDIT_CARD"])

run_test("EC-2",
    "Order ID should NOT be detected as Aadhaar",
    "Order ID: 2345 6789 0123",
    should_reject=["AADHAAR"])

run_test("EC-2b",
    "Real Aadhaar SHOULD be detected",
    "Aadhaar: 2345 6789 0123",
    should_detect=["AADHAAR"])

run_test("EC-3",
    "Version number should NOT be pincode",
    "Version 560001 of the software was released.",
    should_reject=["PINCODE"])

run_test("EC-3b",
    "Real pincode with address context SHOULD be detected",
    "Address: 123 MG Road, Bangalore, Pin: 560001",
    should_detect=["PINCODE"])

run_test("EC-4",
    "Serial number should NOT be phone",
    "Serial: 9876543210",
    should_reject=["PHONE"])

run_test("EC-4b",
    "Real phone SHOULD be detected",
    "Call me at +91-9876543210 for the meeting.",
    should_detect=["PHONE"])

run_test("EC-5",
    "0.0.0.0 should NOT be detected as IP PII",
    "Default IP: 0.0.0.0",
    should_reject=["IP_ADDRESS"])

run_test("EC-6",
    "Policy number (valid Luhn) should NOT be credit card",
    "Policy Number: 4532015112830366",
    should_reject=["CREDIT_CARD"])

run_test("POSITIVE",
    "Full KYC document should detect all PII",
    "Name: Priya Mehta | Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F | Email: priya@gmail.com | Phone: +91-9876543210",
    should_detect=["AADHAAR", "PAN", "EMAIL", "PHONE"])

run_test("POSITIVE-2",
    "Credit card in payment context",
    "Please process payment with card number 4532015112830366, expiry 12/25",
    should_detect=["CREDIT_CARD"])

run_test("EC-11",
    "Clean text should produce no detections",
    "The weather today is nice. I love programming in Python.",
    should_reject=["EMAIL", "PHONE", "AADHAAR", "CREDIT_CARD", "PASSWORD"])

run_test("POSITIVE-3",
    "Bare credit card (no label) should be detected",
    "Here is the number 4532015112830366 for your records.",
    should_detect=["CREDIT_CARD"])

run_test("POSITIVE-4",
    "Email + Password credentials",
    "Email: admin@company.com Password: S3cret!Pass",
    should_detect=["EMAIL", "PASSWORD"])


# ── Summary ──
print("\n" + "═"*60)
print("SUMMARY")
print("═"*60)
passed = sum(1 for _, _, p in test_results if p)
total = len(test_results)

for test_id, desc, p in test_results:
    print(f"  {'✅' if p else '❌'} {test_id}: {desc}")

print(f"\n  Result: {passed}/{total} tests passed")
print("═"*60)

if passed < total:
    sys.exit(1)
