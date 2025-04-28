from django.shortcuts import render
from django.views import View
from .models import SMSDetectionResult, EmailDetectionResult, URLDetectionResult
from detectors.utils import PhishingDetector
import logging

# Initialize the PhishingDetector instance
detector = PhishingDetector()

# Set up logging
logger = logging.getLogger(__name__)

class HomeView(View):
    def get(self, request):
        return render(request, 'index.html')

    def post(self, request):
        input_type = request.POST.get('input_type')
        content = request.POST.get('content')

        # Log input data for debugging
        logger.debug(f"Received input_type: {input_type}, content: {content}")

        # Check if content is empty
        if not content or content.strip() == '':
            return render(request, 'index.html', {'error': 'Content cannot be empty'})

        # Check for valid input_type
        if input_type not in ['email', 'text', 'url']:
            return render(request, 'index.html', {'error': 'Invalid input type'})

        # Process based on the input type and handle prediction
        try:
            if input_type == 'email':
                result, confidence = detector.detect_email(content)
            elif input_type == 'text':
                result, confidence = detector.detect_text(content)
            elif input_type == 'url':
                result, confidence = detector.detect_url(content)
            else:
                return render(request, 'index.html', {'error': 'Invalid input type'})
        except Exception as e:
            # Log the error if there's an exception in the prediction process
            logger.error(f"Error during phishing detection: {str(e)}")
            return render(request, 'index.html', {'error': 'An error occurred during detection'})

        # Validate confidence value
        if confidence is None or not isinstance(confidence, (float, int)):
            logger.error("Invalid confidence value returned from model.")
            return render(request, 'index.html', {'error': 'Invalid confidence value from model'})

        # Save detection result to the appropriate database table
        try:
            if input_type == 'email':
                EmailDetectionResult.objects.create(
                    content=content,
                    result=result,
                    confidence=confidence
                )
            elif input_type == 'text':
                SMSDetectionResult.objects.create(
                    content=content,
                    result=result,
                    confidence=confidence
                )
            elif input_type == 'url':
                URLDetectionResult.objects.create(
                    url=content,
                    result=result,
                    confidence=confidence
                )

            logger.info(f"Detection result saved: {input_type} - {result} with confidence {confidence}")
        except Exception as e:
            logger.error(f"Error saving detection result: {str(e)}")
            return render(request, 'index.html', {'error': 'Error saving the detection result'})

        # Render the results page
        return render(request, 'results.html', {
            'input_type': input_type,
            'content': content,
            'result': result,
            'confidence': round(confidence * 100, 2)
        })

class ResultsView(View):
    def get(self, request):
        return redirect('home')
