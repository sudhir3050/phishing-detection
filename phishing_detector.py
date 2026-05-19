import re

def detect_phishing(email_text):
    print(f"\n--- Analyzing Email Content ---")
    
    # Common phishing keywords and phrases
    phishing_keywords = [
        "urgent", "action required", "verify your account", 
        "suspend", "password reset", "lottery winner", "click here"
    ]
    
    flags_found = []
    score = 0
    
    # 1. Check for suspicious keywords
    for keyword in phishing_keywords:
        if re.search(r"\b" + re.escape(keyword) + r"\b", email_text.lower()):
            flags_found.append(f"Suspicious Phrase: '{keyword}'")
            score += 2
            
    # 2. Check for web links
    if re.search(r"http[s]?://", email_text):
        flags_found.append("Contains web links/URLs")
        score += 1
        
    # 3. Check for fake urgency
    if "!" in email_text and ("account" in email_text.lower() or "bank" in email_text.lower()):
        flags_found.append("High urgency punctuation targeting accounts")
        score += 2

    # Determine Safety Results
    print(f"Phishing Risk Score: {score}/5")
    if score >= 4:
        print("[!!!] RISK STATUS: HIGHLY SUSPICIOUS (Likely Phishing Email)")
    elif score >= 2:
        print("[!] RISK STATUS: SUSPICIOUS (Exercise Caution)")
    else:
        print("[+] RISK STATUS: SAFE (Low Phishing Indicators)")
        
    if flags_found:
        print("\nRed Flags Detected:")
        for flag in flags_found:
            print(f" - {flag}")

# Test the script with a sample phishing scam text
sample_email = "URGENT: Your account has been suspended! Click here to verify your account details immediately."
detect_phishing(sample_email)
