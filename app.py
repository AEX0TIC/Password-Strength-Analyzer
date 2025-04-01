import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
import time
from password_strength_analyzer import PasswordStrengthAnalyzer

# Set page configuration
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #00aeef; /*blue */
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #444;
        margin-bottom: 2rem;
    }
    .strength-header {
        font-size: 1.8rem;
        font-weight: bold;
        margin-top: 1rem;
    }
    .strength-very-weak {
        color: #d9534f; /* Red */
    }
    .strength-weak {
        color: #f0ad4e; /* Orange */
    }
    .strength-moderate {
        color: #5bc0de; /* Light Blue */
    }
    .strength-strong {
        color: #5cb85c; /* Green */
    }
    .strength-very-strong {
        color: #00aeef; /*Blue */
    }
    .feedback-box {
        background-color:  #00344b;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #00aeef;
        margin-top: 1rem;
    }
    .crack-time-box {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 5px;
        margin-top: 1rem;
    }
    .compliance-pass {
        color: #5cb85c;
        font-weight: bold;
    }
    .compliance-fail {
        color: #d9534f;
        font-weight: bold;
    }
    .stProgress > div > div > div > div {
        background-color: #00aeef;
    }
</style>
""", unsafe_allow_html=True)

# Load the model
@st.cache_resource
def load_analyzer():
    model_path = None
    if os.path.exists("models/random_forest_model.joblib"):
        model_path = "models/random_forest_model.joblib"
    elif os.path.exists("models/gradient_boosting_model.joblib"):
        model_path = "models/gradient_boosting_model.joblib"
    elif os.path.exists("password_strength_model.joblib"):
        model_path = "password_strength_model.joblib"
    
    analyzer = PasswordStrengthAnalyzer(model_path=model_path)
    return analyzer

# Function to display strength with appropriate styling
def display_strength(strength_score, strength_label):
    strength_class = {
        0: "strength-very-weak",
        1: "strength-weak",
        2: "strength-moderate",
        3: "strength-strong",
        4: "strength-very-strong"
    }[strength_score]
    
    st.markdown(f"<p class='strength-header {strength_class}'>{strength_label}</p>", unsafe_allow_html=True)
    st.progress((strength_score + 1) / 5)  # +1 to make it 1-5 instead of 0-4 for better visualization

# Function to display crack time estimates
def display_crack_times(crack_times):
    st.markdown("<h3>Estimated Time to Crack</h3>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("<b>Brute Force Attack:</b>", unsafe_allow_html=True)
        st.markdown(f"<p>{crack_times['brute_force']}</p>", unsafe_allow_html=True)
    
    with col2:
        st.markdown("<b>Dictionary Attack:</b>", unsafe_allow_html=True)
        st.markdown(f"<p>{crack_times['dictionary_attack']}</p>", unsafe_allow_html=True)
    
    with col3:
        st.markdown("<b>Targeted Attack:</b>", unsafe_allow_html=True)
        st.markdown(f"<p>{crack_times['targeted_attack']}</p>", unsafe_allow_html=True)
    
    st.markdown(f"<p><b>Most vulnerable to:</b> {crack_times['most_vulnerable_to'].replace('_', ' ')} attack</p>", unsafe_allow_html=True)

# Function to display compliance information
def display_compliance(compliance):
    st.markdown("<h3>Banking Security Compliance</h3>", unsafe_allow_html=True)
    
    if compliance['compliant']:
        st.markdown("<p class='compliance-pass'>✓ Compliant with banking security standards</p>", unsafe_allow_html=True)
    else:
        st.markdown("<p class='compliance-fail'>✗ Not compliant with banking security standards</p>", unsafe_allow_html=True)
        st.markdown("<p><b>Failed requirements:</b></p>", unsafe_allow_html=True)
        
        for req in compliance['failed_requirements']:
            readable_req = req.replace('_', ' ').capitalize()
            st.markdown(f"<p>• {readable_req}</p>", unsafe_allow_html=True)

# Main app
def main():
    # Header
    st.markdown("<h1 class='main-header'>Password Strength Analyzer</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Enterprise-Grade Security for Banking Systems</p>", unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.image("https://upload.wikimedia.org/wikipedia/commons/thumb/7/7b/_logo.svg/1280px-_logo.svg.png", width=200)
    st.sidebar.markdown("## About")
    st.sidebar.markdown("""
    This tool uses advanced machine learning to analyze password strength with a focus on banking security standards.
    
    Features:
    - ML-powered strength analysis
    - Real-time attack simulation
    - Banking compliance checking
    - Personalized feedback
    - AES-256 encryption for secure handling
    """)
    
    st.sidebar.markdown("## Security Standards")
    st.sidebar.markdown("""
    Complies with:
    - GDPR
    - PCI-DSS
    - ISO 27001
    - NIST 800-63B
    - FCA Guidelines
    """)
    
    # Load analyzer
    analyzer = load_analyzer()
    
    # Password input
    password = st.text_input("Enter a password to analyze", type="password")
    
    if password:
        with st.spinner("Analyzing password security..."):
            # Add a small delay to simulate processing for better UX
            time.sleep(0.5)
            
            # Analyze password
            result = analyzer.analyze_password(password)
            
            # Display results
            col1, col2 = st.columns([2, 1])
            
            with col1:
                # Strength score and label
                st.markdown("<h3>Password Strength</h3>", unsafe_allow_html=True)
                display_strength(result['strength_score'], result['strength_label'])
                
                # Feedback
                st.markdown("<h3>Security Feedback</h3>", unsafe_allow_html=True)
                st.markdown(f"<div class='feedback-box'>{result['feedback'].replace('\n', '<br>')}</div>", unsafe_allow_html=True)
                
                # Compliance
                display_compliance(result['compliant_with_banking_standards'])
            
            with col2:
                # Crack time estimates
                st.markdown("<div class='crack-time-box'>", unsafe_allow_html=True)
                display_crack_times(result['crack_time_estimates'])
                st.markdown("</div>", unsafe_allow_html=True)
                
                # Technical details
                st.markdown("<h3>Technical Details</h3>", unsafe_allow_html=True)
                st.markdown(f"<p><b>Entropy:</b> {result['entropy_bits']:.2f} bits</p>", unsafe_allow_html=True)
                
                # Character composition
                st.markdown("<h4>Character Composition</h4>", unsafe_allow_html=True)
                composition = {
                    "Length": len(password),
                    "Uppercase": sum(1 for c in password if c.isupper()),
                    "Lowercase": sum(1 for c in password if c.islower()),
                    "Digits": sum(1 for c in password if c.isdigit()),
                    "Special": sum(1 for c in password if not c.isalnum())
                }
                
                # Create a horizontal bar chart for character composition
                fig, ax = plt.subplots(figsize=(4, 3))
                bars = ax.barh(
                    list(composition.keys())[1:],  # Skip length
                    list(composition.values())[1:],  # Skip length
                    color='#00aeef'
                )
                ax.set_xlabel('Count')
                ax.set_title('Character Types')
                
                # Add count labels to the bars
                for bar in bars:
                    width = bar.get_width()
                    ax.text(width + 0.1, bar.get_y() + bar.get_height()/2, f'{width:.0f}', 
                            ha='left', va='center')
                
                st.pyplot(fig)
    
    # Information section
    st.markdown("---")
    st.markdown("## Why Password Security Matters for Banking")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Risks of Weak Passwords
        - Account takeovers and unauthorized transactions
        - Data breaches exposing customer information
        - Regulatory non-compliance and financial penalties
        - Damage to bank reputation and customer trust
        - Financial losses due to fraud and theft
        """)
    
    with col2:
        st.markdown("""
        ### Banking Security Best Practices
        - Use passwords with at least 12 characters
        - Combine uppercase, lowercase, numbers, and special characters
        - Avoid using personal information or common words
        - Use different passwords for different accounts
        - Change passwords regularly (every 60-90 days)
        - Consider using a password manager
        """)

if __name__ == "__main__":
    main()