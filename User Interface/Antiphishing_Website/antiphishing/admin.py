from django.contrib import admin
from .models import SMSDetectionResult, EmailDetectionResult, URLDetectionResult

# Register the models to the Django admin interface
admin.site.register(SMSDetectionResult)
admin.site.register(EmailDetectionResult)
admin.site.register(URLDetectionResult)
