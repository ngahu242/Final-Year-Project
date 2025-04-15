import pickle
import re
from urllib.parse import urlparse
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer


class PhishingDetector:
    def __init__(self, model_dir='antiphishing/ml_models'):
        # Load pre-trained models
        self.email_model = self._load_model(f'{model_dir}/email_model.pkl')
        self.text_model = self._load_model(f'{model_dir}/text_model.pkl')
        self.url_model = self._load_model(f'{model_dir}/url_model.pkl')

        # Load vectorizers
        self.email_vectorizer = self._load_model(f'{model_dir}/email_vectorizer.pkl')
        self.text_vectorizer = self._load_model(f'{model_dir}/text_vectorizer.pkl')

    def _load_model(self, path):
        """Helper function to load models or vectorizers."""
        try:
            with open(path, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            print(f"Model or vectorizer not found at {path}")
            raise

    def extract_url_features(self, url):
        """Extracts features from URL."""
        if not url:
            raise ValueError("URL cannot be empty")

        parsed = urlparse(url)
        features = {
            'length': len(url),
            'num_digits': sum(c.isdigit() for c in url),
            'num_params': len(parsed.query.split('&')) if parsed.query else 0,
            'num_fragments': len(parsed.fragment.split('#')) if parsed.fragment else 0,
            'num_subdomains': len(parsed.netloc.split('.')) if parsed.netloc else 0,
            'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_at': 1 if '@' in url else 0,
            'has_hyphen': 1 if '-' in parsed.netloc else 0,
        }
        return np.array(list(features.values())).reshape(1, -1)

    def detect_email(self, email_content):
        """Detects phishing in an email."""
        if not email_content:
            raise ValueError("Email content cannot be empty")

        email_vec = self.email_vectorizer.transform([email_content])
        prediction = self.email_model.predict(email_vec)
        proba = self.email_model.predict_proba(email_vec)[0]
        confidence = max(proba)
        return 'phishing' if prediction[0] == 1 else 'legitimate', confidence

    def detect_text(self, text_content):
        """Detects phishing in a text message."""
        if not text_content:
            raise ValueError("Text content cannot be empty")

        text_vec = self.text_vectorizer.transform([text_content])
        prediction = self.text_model.predict(text_vec)
        proba = self.text_model.predict_proba(text_vec)[0]
        confidence = max(proba)
        return 'phishing' if prediction[0] == 1 else 'legitimate', confidence

    def detect_url(self, url):
        """Detects phishing in a URL."""
        if not url:
            raise ValueError("URL cannot be empty")

        features = self.extract_url_features(url)
        prediction = self.url_model.predict(features)
        proba = self.url_model.predict_proba(features)[0]
        confidence = max(proba)
        return 'phishing' if prediction[0] == 1 else 'legitimate', confidence