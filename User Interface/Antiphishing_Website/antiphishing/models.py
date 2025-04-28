from django.db import models

class SMSDetectionResult(models.Model):
    content = models.TextField()  # The content of the SMS
    result = models.CharField(max_length=20)  # 'phishing' or 'legitimate'
    confidence = models.FloatField()  # Confidence level of the prediction
    timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp of when the result was saved

    def __str__(self):
        return f"SMS - {self.result} ({self.confidence * 100:.2f}%)"

class EmailDetectionResult(models.Model):
    content = models.TextField()  # The content of the email
    result = models.CharField(max_length=20)  # 'phishing' or 'legitimate'
    confidence = models.FloatField()  # Confidence level of the prediction
    timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp of when the result was saved

    def __str__(self):
        return f"Email - {self.result} ({self.confidence * 100:.2f}%)"

class URLDetectionResult(models.Model):
    url = models.URLField()  # The URL being detected
    result = models.CharField(max_length=20)  # 'phishing' or 'legitimate'
    confidence = models.FloatField()  # Confidence level of the prediction
    timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp of when the result was saved

    def __str__(self):
        return f"URL - {self.result} ({self.confidence * 100:.2f}%)"
