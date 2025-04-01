import flask
from flask import Flask, request, jsonify
import os
import json
import time
import logging
from password_strength_analyzer import PasswordStrengthAnalyzer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Load the password analyzer
model_path = None
if os.path.exists("models/random_forest_model.joblib"):
    model_path = "models/random_forest_model.joblib"
elif os.path.exists("models/gradient_boosting_model.joblib"):
    model_path = "models/gradient_boosting_model.joblib"
elif os.path.exists("password_strength_model.joblib"):
    model_path = "password_strength_model.joblib"

analyzer = PasswordStrengthAnalyzer(model_path=model_path)
logger.info(f"Loaded password analyzer model from {model_path if model_path else 'default model'}")

# Generate API key for secure access
API_KEY = os.environ.get('PASSWORD_API_KEY', secrets.token_hex(32))
logger.info(f"API Key: {API_KEY[:5]}...{API_KEY[-5:]} (Keep this secure!)")

# Encryption for secure transmission
encryption_key = secrets.token_bytes(32)  # AES-256 key

def encrypt_response(data):
    """Encrypt API response data for secure transmission."""
    iv = secrets.token_bytes(16)  # Initialization vector
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Convert data to JSON string and encode
    json_data = json.dumps(data).encode()
    
    # Pad the data to be a multiple of 16 bytes (AES block size)
    if len(json_data) % 16 != 0:
        json_data += b'\0' * (16 - len(json_data) % 16)
    
    # Encrypt the data
    encrypted_data = encryptor.update(json_data) + encryptor.finalize()
    
    # Return IV and encrypted data as hex strings
    return {
        "iv": iv.hex(),
        "data": encrypted_data.hex()
    }

@app.before_request
def verify_api_key():
    """Verify API key for all requests except health check."""
    if request.endpoint == 'health':
        return
    
    api_key = request.headers.get('X-API-Key')
    if not api_key or api_key != API_KEY:
        logger.warning(f"Invalid API key attempt from {request.remote_addr}")
        return jsonify({"error": "Invalid or missing API key"}), 401

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": time.time()})

@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    """Analyze password strength."""
    start_time = time.time()
    
    # Get request data
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({"error": "Missing password parameter"}), 400
    
    password = data['password']
    encrypt_response_flag = data.get('encrypt_response', False)
    
    # Optional context for more accurate analysis
    context = data.get('context', {})
    username = context.get('username', '')
    email = context.get('email', '')
    
    # Log the request (without the actual password)
    logger.info(f"Password analysis request received from {request.remote_addr} with context: {context}")
    
    # Check for common username/email patterns in password
    additional_feedback = []
    if username and username.lower() in password.lower():
        additional_feedback.append("Your password contains your username, which makes it easy to guess.")
    if email and email.split('@')[0].lower() in password.lower():
        additional_feedback.append("Your password contains part of your email address, which makes it easy to guess.")
    
    # Analyze the password
    try:
        result = analyzer.analyze_password(password)
        
        # Add any additional feedback
        if additional_feedback:
            result['feedback'] = result['feedback'] + "\n" + "\n".join(additional_feedback)
        
        # Add processing time
        result['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
        
        # Add timestamp
        result['timestamp'] = time.time()
        
        # Encrypt response if requested
        if encrypt_response_flag:
            encrypted_result = encrypt_response(result)
            return jsonify(encrypted_result)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error analyzing password: {str(e)}")
        return jsonify({"error": "Error analyzing password", "details": str(e)}), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """Analyze multiple passwords in batch mode."""
    start_time = time.time()
    
    # Get request data
    data = request.get_json()
    if not data or 'passwords' not in data:
        return jsonify({"error": "Missing passwords parameter"}), 400
    
    passwords = data['passwords']
    if not isinstance(passwords, list):
        return jsonify({"error": "Passwords must be provided as a list"}), 400
    
    # Limit batch size
    if len(passwords) > 100:
        return jsonify({"error": "Batch size limited to 100 passwords"}), 400
    
    # Log the request
    logger.info(f"Batch analysis request received from {request.remote_addr} for {len(passwords)} passwords")
    
    # Analyze each password
    results = []
    for pwd in passwords:
        try:
            result = analyzer.analyze_password(pwd)
            results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing password in batch: {str(e)}")
            results.append({"error": "Error analyzing password", "details": str(e)})
    
    # Add processing time and timestamp
    response = {
        "results": results,
        "count": len(results),
        "processing_time_ms": round((time.time() - start_time) * 1000, 2),
        "timestamp": time.time()
    }
    
    return jsonify(response)

@app.route('/api/compliance-check', methods=['POST'])
def compliance_check():
    """Check if a password meets banking compliance standards."""
    # Get request data
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({"error": "Missing password parameter"}), 400
    
    password = data['password']
    compliance_type = data.get('compliance_type', 'banking')  # Default to banking standards
    
    # Log the request
    logger.info(f"Compliance check request received from {request.remote_addr} for type: {compliance_type}")
    
    try:
        # Analyze the password
        result = analyzer.analyze_password(password)
        
        # Extract compliance information
        compliance_info = result['compliant_with_banking_standards']
        
        # Add compliance type
        compliance_info['compliance_type'] = compliance_type
        
        # Add timestamp
        compliance_info['timestamp'] = time.time()
        
        return jsonify(compliance_info)
    
    except Exception as e:
        logger.error(f"Error checking compliance: {str(e)}")
        return jsonify({"error": "Error checking compliance", "details": str(e)}), 500

@app.route('/api/documentation', methods=['GET'])
def documentation():
    """API documentation endpoint."""
    docs = {
        "api_version": "1.0",
        "description": "Barclays Password Strength Analyzer API",
        "endpoints": [
            {
                "path": "/health",
                "method": "GET",
                "description": "Health check endpoint",
                "requires_auth": False
            },
            {
                "path": "/api/analyze",
                "method": "POST",
                "description": "Analyze a single password",
                "requires_auth": True,
                "parameters": {
                    "password": "The password to analyze",
                    "encrypt_response": "Boolean flag to encrypt the response (optional)",
                    "context": "Additional context like username, email (optional)"
                }
            },
            {
                "path": "/api/batch-analyze",
                "method": "POST",
                "description": "Analyze multiple passwords in batch",
                "requires_auth": True,
                "parameters": {
                    "passwords": "List of passwords to analyze (max 100)"
                }
            },
            {
                "path": "/api/compliance-check",
                "method": "POST",
                "description": "Check if a password meets compliance standards",
                "requires_auth": True,
                "parameters": {
                    "password": "The password to check",
                    "compliance_type": "Type of compliance to check (default: banking)"
                }
            },
            {
                "path": "/api/documentation",
                "method": "GET",
                "description": "API documentation",
                "requires_auth": True
            }
        ],
        "authentication": "API key required in X-API-Key header for all endpoints except /health"
    }
    
    return jsonify(docs)

# Example usage with curl:
"""
# Health check
curl -X GET http://localhost:5000/health

# Analyze a password
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"password": "YourPasswordHere", "context": {"username": "john_doe", "email": "john@example.com"}}'

# Batch analyze
curl -X POST http://localhost:5000/api/batch-analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"passwords": ["password1", "Secure123!", "Tr0ub4dor&3"]}'

# Compliance check
curl -X POST http://localhost:5000/api/compliance-check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"password": "YourPasswordHere", "compliance_type": "banking"}'

# Get API documentation
curl -X GET http://localhost:5000/api/documentation \
  -H "X-API-Key: YOUR_API_KEY"
"""

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Print startup message
    print(f"\n{'='*50}")
    print(f"Barclays Password Strength Analyzer API")
    print(f"Running on port {port}")
    print(f"API Key: {API_KEY[:5]}...{API_KEY[-5:]} (Keep this secure!)")
    print(f"{'='*50}\n")
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=False)