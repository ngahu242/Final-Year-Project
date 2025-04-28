import argparse
from detectors.utils import PhishingDetector

def main():
    # Initialize the phishing detector
    detector = PhishingDetector()

    # Display welcome message and menu options
    print("Welcome to the Anti-Phishing Detection System")
    print("Please choose an option:")
    print("1. Check an email for phishing")
    print("2. Check a URL for phishing")
    print("3. Check an SMS for phishing")
    print("4. Exit")

    # Prompt user for choice
    choice = input("Enter your choice (1/2/3/4): ")

    # Handle user's choice
    if choice == '1':
        email = input("Enter the email content: ")
        result, confidence = detector.detect_email(email)
        print(f"🔍 Result: {result.capitalize()} | Confidence: {confidence:.2f}")
    elif choice == '2':
        url = input("Enter the URL: ")
        result, confidence = detector.detect_url(url)
        print(f"🔍 Result: {result.capitalize()} | Confidence: {confidence:.2f}")
    elif choice == '3':
        sms = input("Enter the SMS content: ")
        result, confidence = detector.detect_text(sms)
        print(f"🔍 Result: {result.capitalize()} | Confidence: {confidence:.2f}")
    elif choice == '4':
        print("Exiting the Anti-Phishing Detection System. Stay safe!")
        return
    else:
        print("Invalid choice! Please select a valid option.")
        return

if __name__ == "__main__":
    main()
