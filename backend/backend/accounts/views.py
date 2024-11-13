# accounts/views.py

from django.views import View
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
import json
import logging

# Set up logging for debugging
logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(View):
    def post(self, request):
        try:
            logger.info("Received POST request to RegisterView")

            # Attempt to parse JSON data from the request body
            try:
                data = json.loads(request.body)
                logger.info("Request body successfully parsed")
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON: %s", e)
                return JsonResponse({"error": "Invalid JSON format"}, status=400)

            # Extract username, password, and email from the parsed data
            username = data.get("username")
            password = data.get("password")
            email = data.get("email")

            # Log extracted values for debugging
            logger.debug("Username: %s, Email: %s", username, email)

            # Validate fields
            if not username or not password or not email:
                logger.error("Missing required fields")
                return JsonResponse({"error": "Username, password, and email are required"}, status=400)

            # Check if the username already exists
            if User.objects.filter(username=username).exists():
                logger.warning("Username already exists: %s", username)
                return JsonResponse({"error": "Username already exists"}, status=400)

            # Check if the email already exists
            if User.objects.filter(email=email).exists():
                logger.warning("Email already exists: %s", email)
                return JsonResponse({"error": "Email already exists"}, status=400)

            # Create a new user
            try:
                user = User.objects.create_user(username=username, password=password, email=email)
                logger.info("User created successfully: %s", username)
            except Exception as e:
                logger.error("Failed to create user: %s", e)
                return JsonResponse({"error": "Failed to create user"}, status=500)

            return JsonResponse({"message": "User registered successfully"}, status=201)

        except Exception as e:
            # Catch any other unexpected exceptions
            logger.exception("Unexpected error in RegisterView: %s", e)
            return JsonResponse({"error": "An unexpected error occurred"}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    def post(self, request):
        try:
            logger.info("Received POST request to LoginView")

            # Attempt to parse JSON data from the request body
            try:
                data = json.loads(request.body)
                logger.info("Request body successfully parsed")
            except json.JSONDecodeError as e:
                logger.error("Failed to parse JSON: %s", e)
                return JsonResponse({"error": "Invalid JSON format"}, status=400)

            # Extract username and password from the parsed data
            username = data.get("username")
            password = data.get("password")

            # Log extracted values for debugging
            logger.debug("Username: %s", username)

            # Validate that username and password are provided
            if not username or not password:
                logger.error("Missing username or password")
                return JsonResponse({"error": "Username and password are required"}, status=400)

            # Authenticate the user
            user = authenticate(request, username=username, password=password)
            if user is not None:
                # Log in the user
                login(request, user)
                logger.info("User authenticated and logged in: %s", username)

                # Generate tokens for the user
                try:
                    refresh = RefreshToken.for_user(user)
                    logger.info("JWT tokens generated successfully for user: %s", username)
                except Exception as e:
                    logger.error("Failed to generate tokens: %s", e)
                    return JsonResponse({"error": "Token generation failed"}, status=500)

                # Return the access and refresh tokens
                return JsonResponse({
                    "message": "User logged in successfully",
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                }, status=200)
            else:
                logger.warning("Invalid username or password for user: %s", username)
                return JsonResponse({"error": "Invalid username or password"}, status=401)

        except Exception as e:
            # Catch any other unexpected exceptions
            logger.exception("Unexpected error in LoginView: %s", e)
            return JsonResponse({"error": "An unexpected error occurred"}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class VerifyTokenView(View):
    def post(self, request):
        token = request.headers.get('Authorization')  # Get the token from the Authorization header
        
        if token is None:
            return JsonResponse({"error": "No token provided"}, status=401)
        
        # Remove "Bearer " prefix if present
        token = token.split(" ")[1] if " " in token else token
        
        try:
            # Use JWT Authentication to validate the token
            validated_token = JWTAuthentication().get_validated_token(token)

            # Retrieve user information based on user_id from the token
            user_id = validated_token["user_id"]
            user = User.objects.get(id=user_id)

            # Convert the validated token to a dictionary
            response_data = {
                "message": "Token is valid",
                "decoded": {
                    "user_id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "exp": validated_token["exp"],
                    "iat": validated_token["iat"],
                }
            }
            return JsonResponse(response_data, status=200)
        except TokenError as e:
            print(e)
            return JsonResponse({"error": "Token is invalid or expired"}, status=401)
        except User.DoesNotExist:
            return JsonResponse({"error": "User does not exist"}, status=404)
        except Exception as e:
            print(e)
            return JsonResponse({"error": "Something unexpected happened"}, status=500)        
        

@method_decorator(csrf_exempt, name='dispatch')
class UpdateAccountView(View):
    def put(self, request):
    
        token = request.headers.get('Authorization')
        
        if token is None:
            return JsonResponse({"error": "No token provided"}, status=401)
        
        token = token.split(" ")[1] if " " in token else token
        
        try:
            # Validate the token
            validated_token = JWTAuthentication().get_validated_token(token)
            
            # Retrieve user information from the token
            user_id = validated_token["user_id"]
            user = User.objects.get(id=user_id)
            
            # Get updated data from the request body
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')

            # Update user fields if new values are provided
            if username:
                user.username = username
            if email:
                user.email = email
            if password:
                user.set_password(password)
                
            user.save()

            return JsonResponse({
                "message": "User details updated successfully",
                "user": {
                    "username": user.username,
                    "email": user.email,
                }
            }, status=200)
        
        except TokenError as e:
            print(e)
            return JsonResponse({"error": "Token is invalid or expired"}, status=401)
        except User.DoesNotExist as e:
            print(e)
            return JsonResponse({"error": "User does not exist"}, status=404)
        except json.JSONDecodeError as e:
            print(e)
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
        except Exception as e:
            print(e)
            return JsonResponse({"error": "Something unexpected happened"}, status=500)
