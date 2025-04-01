# Standalone Password Strength Analyzer

This is a standalone version of the Barclays Password Strength Analyzer that works without requiring API integration or web servers. It uses machine learning to evaluate password strength based on features like entropy, character composition, and pattern detection.

## Features

- ML-powered password strength analysis
- Real-time cracking time estimation
- Banking security compliance checking
- Personalized security feedback
- Batch analysis of multiple passwords
- Visualization of password strength distribution

## Requirements

The following Python packages are required:

```
numpy>=1.20.0
pandas>=1.3.0
scikit-learn>=1.0.0
joblib>=1.1.0
matplotlib>=3.4.0
seaborn>=0.11.0
cryptography>=36.0.0
```

You can install them using:

```
pip install -r requirements.txt
```

## Usage

The standalone analyzer provides several commands:

### Analyze a single password

```
python standalone_password_analyzer.py analyze "YourPasswordHere"
```

### Analyze multiple passwords from a file

Create a text file with one password per line, then run:

```
python standalone_password_analyzer.py batch passwords.txt
```

This will analyze all passwords in the file and generate a summary with visualization.

### Train the model

If you don't have a pre-trained model or want to retrain it:

```
python standalone_password_analyzer.py train
```

### Test with example passwords

```
python standalone_password_analyzer.py test
```

## How It Works

The analyzer extracts various features from passwords including:

1. **Basic features**: Length, character composition (uppercase, lowercase, digits, special characters)
2. **Entropy**: Information-theoretic measure of randomness
3. **Pattern detection**: Common sequences, repeated characters, dictionary words
4. **Sequential characters**: Detecting keyboard patterns like "qwerty" or "12345"

These features are fed into a machine learning model (Random Forest, Gradient Boosting, or Neural Network) that predicts the password strength on a scale from 0 (Very Weak) to 4 (Very Strong).

The analyzer also estimates how long it would take to crack the password using different attack methods (brute force, dictionary attack, targeted attack) and checks compliance with banking security standards.

## Security Note

This tool handles passwords securely using encryption for sensitive operations. However, it's recommended to use this tool in a secure environment and avoid analyzing sensitive passwords on shared systems.