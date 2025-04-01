import argparse
import os
import joblib
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from password_strength_analyzer import PasswordStrengthAnalyzer

def load_analyzer():
    """Load the password strength analyzer with the best available model."""
    model_path = None
    if os.path.exists("models/random_forest_model.joblib"):
        model_path = "models/random_forest_model.joblib"
    elif os.path.exists("models/gradient_boosting_model.joblib"):
        model_path = "models/gradient_boosting_model.joblib"
    elif os.path.exists("password_strength_model.joblib"):
        model_path = "password_strength_model.joblib"
    
    analyzer = PasswordStrengthAnalyzer(model_path=model_path)
    return analyzer

def analyze_password(password):
    """Analyze a password and print detailed results."""
    analyzer = load_analyzer()
    
    print("\nAnalyzing password security...")
    start_time = time.time()
    result = analyzer.analyze_password(password)
    analysis_time = time.time() - start_time
    
    # Print results
    print("\n" + "=" * 50)
    print(f"Password: {'*' * len(password)}")
    print(f"Strength: {result['strength_label']} ({result['strength_score']}/4)")
    print(f"Entropy: {result['entropy_bits']:.2f} bits")
    print(f"Analysis completed in {analysis_time:.3f} seconds")
    print("=" * 50)
    
    # Crack time estimates
    print("\nEstimated crack times:")
    for attack, time_estimate in result['crack_time_estimates'].items():
        if attack != 'most_vulnerable_to':
            print(f"  - {attack.replace('_', ' ').title()}: {time_estimate}")
    print(f"\nMost vulnerable to: {result['crack_time_estimates']['most_vulnerable_to'].replace('_', ' ')} attack")
    
    # Compliance information
    compliance = result['compliant_with_banking_standards']
    print("\nBanking Security Compliance:")
    if compliance['compliant']:
        print("✓ Compliant with banking security standards")
    else:
        print("✗ Not compliant with banking security standards")
        print("Failed requirements:")
        for req in compliance['failed_requirements']:
            readable_req = req.replace('_', ' ').capitalize()
            print(f"  • {readable_req}")
    
    # Feedback
    print("\nSecurity Feedback:")
    print(result['feedback'])
    
    return result

def batch_analyze(file_path):
    """Analyze multiple passwords from a file."""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return
    
    analyzer = load_analyzer()
    results = []
    
    try:
        with open(file_path, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        print(f"\nAnalyzing {len(passwords)} passwords from {file_path}...")
        
        for i, password in enumerate(passwords, 1):
            print(f"\nPassword {i}/{len(passwords)}:")
            result = analyzer.analyze_password(password)
            results.append(result)
            
            # Print brief results
            print(f"Strength: {result['strength_label']} ({result['strength_score']}/4)")
            print(f"Compliant: {'Yes' if result['compliant_with_banking_standards']['compliant'] else 'No'}")
        
        # Generate summary statistics
        strength_counts = {}
        for r in results:
            strength = r['strength_label']
            strength_counts[strength] = strength_counts.get(strength, 0) + 1
        
        compliant_count = sum(1 for r in results if r['compliant_with_banking_standards']['compliant'])
        
        # Print summary
        print("\n" + "=" * 50)
        print(f"Batch Analysis Summary ({len(passwords)} passwords)")
        print("=" * 50)
        print("\nStrength Distribution:")
        for strength, count in strength_counts.items():
            percentage = (count / len(passwords)) * 100
            print(f"  - {strength}: {count} ({percentage:.1f}%)")
        
        print(f"\nCompliant with banking standards: {compliant_count} ({(compliant_count/len(passwords))*100:.1f}%)")
        
        # Generate visualization if matplotlib is available
        try:
            plt.figure(figsize=(10, 6))
            strengths = list(strength_counts.keys())
            counts = list(strength_counts.values())
            
            # Sort by strength level
            strength_order = {"Very Weak": 0, "Weak": 1, "Moderate": 2, "Strong": 3, "Very Strong": 4}
            sorted_items = sorted(zip(strengths, counts), key=lambda x: strength_order.get(x[0], 5))
            strengths, counts = zip(*sorted_items) if sorted_items else ([], [])
            
            # Create color map
            colors = ['#d9534f', '#f0ad4e', '#5bc0de', '#5cb85c', '#00aeef']
            colors = [colors[strength_order[s]] for s in strengths]
            
            plt.bar(strengths, counts, color=colors)
            plt.title('Password Strength Distribution')
            plt.xlabel('Strength Level')
            plt.ylabel('Number of Passwords')
            plt.tight_layout()
            
            # Save the plot
            output_dir = 'plots'
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, 'batch_analysis_results.png')
            plt.savefig(output_file)
            print(f"\nVisualization saved to {output_file}")
            
        except Exception as e:
            print(f"\nCould not generate visualization: {e}")
    
    except Exception as e:
        print(f"Error during batch analysis: {e}")

def generate_training_data():
    """Generate synthetic training data and train the model."""
    print("\n===== Generating Synthetic Training Data =====")
    
    # Very weak passwords
    very_weak = [
        "password", "123456", "qwerty", "admin", "welcome",
        "login", "abc123", "letmein", "monkey", "1234567890"
    ]
    
    # Weak passwords
    weak = [
        "Password1", "Qwerty123", "Admin2023", "Barclays1",
        "Summer2023", "Winter2023", "London2023", "Banking1",
        "Secure123", "Finance22"
    ]
    
    # Moderate passwords
    moderate = [
        "Password123!", "Qwerty123$", "Admin2023#", "Barclays1@",
        "Summer2023!", "Winter2023$", "London2023#", "Banking1@",
        "Secure123!", "Finance22$"
    ]
    
    # Strong passwords
    strong = [
        "P@ssw0rd123!456", "Qw3rty!$#456", "Adm1n2023#$%", "B@rcl4ys1@2023",
        "Summ3r2023!$%", "W1nt3r2023$#@", "L0nd0n2023#!@", "B@nk1ng1@2023",
        "S3cur3123!@#", "F1n@nc322$%^"
    ]
    
    # Very strong passwords
    very_strong = [
        "P@$$w0rd123!456&*()", "Qw3rty!$#456^&*()", "Adm1n2023#$%^&*()",
        "B@rcl4ys1@2023!#$%", "Summ3r2023!$%^&*()", "W1nt3r2023$#@!%^&",
        "L0nd0n2023#!@$%^&", "B@nk1ng1@2023#$%^", "S3cur3123!@#$%^&",
        "F1n@nc322$%^&*()"
    ]
    
    # Combine all passwords and labels
    all_passwords = very_weak + weak + moderate + strong + very_strong
    all_labels = [0]*10 + [1]*10 + [2]*10 + [3]*10 + [4]*10
    
    # Train the model
    print("Training the model...")
    analyzer = PasswordStrengthAnalyzer()
    analyzer.train(all_passwords, all_labels)
    
    # Save the trained model
    analyzer.save_model("password_strength_model.joblib")
    print("Model trained and saved to password_strength_model.joblib")

def main():
    parser = argparse.ArgumentParser(description="Standalone Password Strength Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Single password analysis command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single password")
    analyze_parser.add_argument("password", help="Password to analyze")
    
    # Batch analysis command
    batch_parser = subparsers.add_parser("batch", help="Analyze multiple passwords from a file")
    batch_parser.add_argument("file", help="File containing passwords (one per line)")
    
    # Train model command
    train_parser = subparsers.add_parser("train", help="Generate training data and train the model")
    
    # Test command with example passwords
    test_parser = subparsers.add_parser("test", help="Test with example passwords")
    
    args = parser.parse_args()
    
    if args.command == "analyze":
        analyze_password(args.password)
    elif args.command == "batch":
        batch_analyze(args.file)
    elif args.command == "train":
        generate_training_data()
    elif args.command == "test":
        # Test with some example passwords
        test_passwords = [
            "password123",
            "Barclays2023",
            "P@ssw0rd123",
            "S3cur3B@nk1ng2023!",
            "Tr0ub4dor&3"
        ]
        
        print("\nTesting with example passwords:")
        for pwd in test_passwords:
            analyze_password(pwd)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()