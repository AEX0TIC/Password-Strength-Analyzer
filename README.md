# Password Strength Analyzer

A machine learning-based password strength analyzer designed specifically for banking security needs. This project was developed for the Barclays Hackathon (Hack o Hire) to demonstrate how advanced ML techniques can enhance password security in financial institutions.

## 🔒 Project Overview

This Password Strength Analyzer uses sophisticated machine learning algorithms to evaluate password strength with a focus on banking security standards. It goes beyond traditional rule-based approaches by incorporating:

- **ML-powered Entropy Analysis**: Evaluates password complexity using multiple features
- **Adversarial Training**: Trained against common password cracking techniques
- **Real-time Attack Simulation**: Estimates time-to-crack using different attack methods
- **Banking Compliance Checking**: Verifies passwords against financial security standards
- **Personalized Feedback**: Provides specific recommendations for improvement
- **AES-256 Encryption**: Ensures secure password handling during analysis

## 🚀 Features

- **Enterprise-Grade Security Compliance**: Aligns with financial security standards (GDPR, NIST, PCI-DSS)
- **Comprehensive Password Analysis**: Evaluates multiple aspects of password strength
- **Attack Scenario Simulation**: Predicts which attack method will likely break a password
- **Interactive Web Interface**: User-friendly application for password testing
- **Detailed Feedback**: Provides specific recommendations for improving password security
- **Banking-Specific Security Rules**: Customized for financial institution requirements

## 📊 Technical Implementation

- **Machine Learning Models**: Random Forest, Gradient Boosting, Neural Networks, and SVM
- **Feature Engineering**: Extracts 10+ features from passwords for analysis
- **Model Training & Evaluation**: Comprehensive model selection and hyperparameter tuning
- **Visualization**: Detailed charts and graphs for password analysis
- **Secure Handling**: AES-256 encryption for password evaluation

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/barclays-password-analyzer.git
cd barclays-password-analyzer

# Install dependencies
pip install -r requirements.txt
```

## 🔧 Usage

### Running the Web Application

```bash
streamlit run app.py
```

This will start the web application, which you can access at http://localhost:8501 in your browser.

### Training the Model

```bash
python train_models.py
```

This will generate a dataset, train multiple models, and save the best model for use in the application.

### Using the Analyzer in Your Code

```python
from password_strength_analyzer import PasswordStrengthAnalyzer

# Create analyzer instance
analyzer = PasswordStrengthAnalyzer()

# Analyze a password
result = analyzer.analyze_password("YourPasswordHere")

# Print results
print(f"Strength: {result['strength_label']} ({result['strength_score']}/4)")
print(f"Feedback: {result['feedback']}")
```

## 🔍 Why This Matters to Barclays

- **Reduced Fraud Risk**: Stronger passwords mean fewer account takeovers
- **Regulatory Compliance**: Helps meet GDPR, PCI-DSS, and ISO 27001 requirements
- **Enhanced Customer Security**: Protects customer accounts and sensitive data
- **Employee Security Education**: Teaches staff about password best practices
- **Cost Savings**: Prevents financial losses due to security breaches

## 🔮 Future Enhancements

- Integration with Barclays' existing authentication systems
- Multi-factor authentication (MFA) recommendations
- Real-time breach database checking
- Behavioral analysis for suspicious password changes
- Mobile application for on-the-go password security checks

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- For the opportunity to develop this solution
- The scikit-learn team for their excellent machine learning library
- Streamlit for making it easy to create interactive web applications
