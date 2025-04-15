from django.db import models

class DetectionResult(models.Model):
    input_type = models.CharField(max_length=10, choices=[('email', 'Email'), ('text', 'Text'), ('url', 'URL')])
    content = models.TextField()
    result = models.CharField(max_length=20)
    confidence = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.input_type} - {self.result}"
