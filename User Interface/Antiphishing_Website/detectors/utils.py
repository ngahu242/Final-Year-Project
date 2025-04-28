import pickle
import re
import numpy as np
from urllib.parse import urlparse
from pathlib import Path
import joblib
import warnings

# Load the SMS pipeline
pipeline_path = Path(__file__).parent.parent / "models" / "sms_pipeline.joblib"
sms_pipeline = joblib.load(pipeline_path)

class PhishingDetector:
    def __init__(self, model_dir='antiphishing/ml_models'):
        self.model_dir = model_dir
        # Load pre-trained models
        #We used SVM for the email Model
        self.email_model = self._load_model(f'{self.model_dir}/email_model.pkl')
        #We used SVM
        self.sms_model = self._load_model(f'{self.model_dir}/sms_model.pkl')
        #We used RandoForest Classfier
        self.url_model = self._load_model(f'{self.model_dir}/url_model.pkl')

        # Load vectorizers
        self.email_vectorizer = self._load_model(f'{self.model_dir}/email_vectorizer.pkl')
        self.sms_vectorizer = self._load_model(f'{self.model_dir}/sms_vectorizer.pkl')

    def _load_model(self, path):
        """Helper function to load models or vectorizers."""
        try:
            with open(path, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            print(f"Model or vectorizer not found at {path}")
            raise
        except Exception as e:
            print(f"Error loading {path}: {e}")
            raise

    def extract_url_features(self, url):
        """Extracts features from URL."""
        if not url:
            raise ValueError("URL cannot be empty")

        parsed = urlparse(url)

        # Extract 31 features, matching the training feature set
        features = {
            'length': len(url),  # Length of the URL
            'num_digits': sum(c.isdigit() for c in url),  # Number of digits
            'num_params': len(parsed.query.split('&')) if parsed.query else 0,  # Number of query parameters
            'num_fragments': len(parsed.fragment.split('#')) if parsed.fragment else 0,  # Number of fragments
            'num_subdomains': len(parsed.netloc.split('.')) if parsed.netloc else 0,  # Number of subdomains
            'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
            'has_https': 1 if parsed.scheme == 'https' else 0,  # Is the scheme HTTPS?
            'has_at': 1 if '@' in url else 0,  # Does the URL contain '@' symbol?
            'has_hyphen': 1 if '-' in parsed.netloc else 0,  # Does the domain contain a hyphen?
            'num_dots': url.count('.'),  # Number of dots in the domain
            'num_slashes': url.count('/'),  # Number of slashes
            'is_short': 1 if len(url) < 50 else 0,  # Is the URL short?
            'num_uppercase': sum(1 for c in url if c.isupper()),  # Count of uppercase letters
            'num_lowercase': sum(1 for c in url if c.islower()),  # Count of lowercase letters
            'num_special_chars': sum(1 for c in url if not c.isalnum() and c != '.' and c != '/'),
            'is_ip_address': 1 if re.match(r'(\d{1,3}\.){3}\d{1,3}', parsed.netloc) else 0,
            'num_subdomains_greater_than_2': 1 if len(parsed.netloc.split('.')) > 2 else 0,  # More than 2 subdomains
            'is_very_long': 1 if len(url) > 100 else 0,  # Is the URL very long?
            'has_www': 1 if 'www' in parsed.netloc else 0,  # Does the domain contain 'www'?
            'has_query': 1 if parsed.query else 0,  # Does the URL have a query string?
            'has_fragment': 1 if parsed.fragment else 0,  # Does the URL have a fragment?
            'is_secure': 1 if parsed.scheme == 'https' else 0,  # Is the URL secure (HTTPS)?
            'has_mixed_case': 1 if any(c.isupper() for c in url) and any(c.islower() for c in url) else 0,
            'num_https_in_query': parsed.query.count('https'),  # Count of 'https' in query parameters
            'is_domain_known': 1 if parsed.netloc.endswith('.com') else 0,  # Known domain (.com)
            'has_unicode': 1 if any(ord(c) > 127 for c in url) else 0,  # URL contains Unicode characters?
            'num_ports': len([x for x in parsed.netloc.split(':') if x]) if ':' in parsed.netloc else 0,
            'is_encoded': 1 if '%' in url else 0,  # Is the URL URL-encoded?
            'has_underscore': 1 if '_' in url else 0,  # Does the URL contain underscores?
            'has_digit_domain': 1 if any(c.isdigit() for c in parsed.netloc) else 0,  # Does the domain have digits?
            'has_long_query': 1 if len(parsed.query) > 50 else 0,  # Is the query string long?
        }

        # Check if the number of features is 31
        assert len(features) == 31, f"Feature count mismatch: {len(features)} features found, but 31 are expected."

        # Convert the dictionary of features into a NumPy array and reshape it to match the expected input for the model
        feature_array = np.array(list(features.values())).reshape(1, -1)  # Shape should be (1, 31)

        # Ensure no NaN values
        if np.any(np.isnan(feature_array)):
            feature_array = np.nan_to_num(feature_array)  # Replace NaN with 0

        return feature_array

    def detect_email(self, email_content):
        """Detects phishing in an email."""
        if not email_content:
            raise ValueError("Email content cannot be empty")

        # Vectorize the email content using the email_vectorizer
        email_vec = self.email_vectorizer.transform([email_content])

        # Get the prediction (0 for legitimate, 1 for phishing)
        prediction = self.email_model.predict(email_vec)

        # Optionally, you can use the decision function to get a measure of confidence (not probabilities)
        if hasattr(self.email_model, 'decision_function'):
            confidence = abs(self.email_model.decision_function(email_vec)[0])
        else:
            # Fallback: If no decision_function, use a default confidence value
            confidence = 0.7  # Or some default value, as `predict()` doesn't provide confidence

        # Return phishing or legitimate result and the confidence value
        return 'phishing' if prediction[0] == 1 else 'legitimate', confidence

    def detect_text(self, sms_content):
        """Detects phishing in a text message (SMS)."""
        if not sms_content:
            raise ValueError("SMS content cannot be empty")

        # Vectorize the SMS content using the sms_vectorizer
        sms_vec = self.sms_vectorizer.transform([sms_content])

        # Get the prediction (0 for legitimate, 1 for phishing)
        prediction = self.sms_model.predict(sms_vec)

        # Optionally, you can use the decision function to get a measure of confidence (not probabilities)
        if hasattr(self.sms_model, 'decision_function'):
            confidence = abs(self.sms_model.decision_function(sms_vec)[0])
        else:
            # Fallback: If no decision_function, use a default confidence value
            confidence = 0.7  # Or some default value, as `predict()` doesn't provide confidence

        # Return phishing or legitimate result and the confidence value
        return 'phishing' if prediction == 1 else 'legitimate', confidence

    def detect_url(self, url):
        """Detects phishing in a URL."""
        if not url:
            raise ValueError("URL cannot be empty")

        # Extract features and reshape them correctly
        features = self.extract_url_features(url)

        # Prediction and probability estimation
        prediction = self.url_model.predict(features)
        if hasattr(self.url_model, "predict_proba"):
            proba = self.url_model.predict_proba(features)[0]
            confidence = max(proba)
        else:
            decision_scores = self.url_model.decision_function(features)
            confidence = abs(decision_scores[0])  # The further the score from 0, the more confident

        return 'phishing' if prediction[0] == 1 else 'legitimate', confidence
