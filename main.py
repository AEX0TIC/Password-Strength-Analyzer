import os
import argparse
import subprocess
import time
import sys

def check_dependencies():
    """Check if required dependencies are installed."""
    try:
        import numpy
        import pandas
        import sklearn
        import joblib
        import matplotlib
        import seaborn
        import streamlit
        import cryptography
        print("✓ All required dependencies are installed.")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please install required dependencies using: pip install -r requirements.txt")
        return False

def generate_dataset():
    """Generate the password dataset."""
    print("\n===== Generating Password Dataset =====")
    os.makedirs("data", exist_ok=True)
    import generate_dataset
    df = generate_dataset.generate_dataset("data/password_dataset.csv", n_samples=5000)
    
    # Split into train and test sets
    from sklearn.model_selection import train_test_split
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['strength'])
    
    # Save train and test sets
    train_df.to_csv("data/train_dataset.csv", index=False)
    test_df.to_csv("data/test_dataset.csv", index=False)
    
    print(f"Training set: {len(train_df)} passwords")
    print(f"Test set: {len(test_df)} passwords")
    print("Dataset generation complete.")

def train_model():
    """Train the password strength model."""
    print("\n===== Training Password Strength Model =====")
    os.makedirs("models", exist_ok=True)
    import train_models
    best_model, model_path = train_models.main()
    print(f"Model training complete. Model saved to {model_path}")
    return model_path

def run_web_app():
    """Run the Streamlit web application."""
    print("\n===== Starting Web Application =====")
    print("Starting Streamlit server...")
    cmd = [sys.executable, "-m", "streamlit", "run", "app.py"]
    process = subprocess.Popen(cmd)
    print("\nWeb application is running!")
    print("Open your browser and go to: http://localhost:8501")
    print("Press Ctrl+C to stop the application.")
    try:
        process.wait()
    except KeyboardInterrupt:
        process.terminate()
        print("\nWeb application stopped.")

def run_api_server():
    """Run the API server."""
    print("\n===== Starting API Server =====")
    print("Starting Flask API server...")
    cmd = [sys.executable, "api_integration.py"]
    process = subprocess.Popen(cmd)
    print("\nAPI server is running!")
    print("API is available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server.")
    try:
        process.wait()
    except KeyboardInterrupt:
        process.terminate()
        print("\nAPI server stopped.")

def run_hashcat_simulation():
    """Run the Hashcat simulation."""
    print("\n===== Running Hashcat Simulation =====")
    import hashcat_simulation
    simulator = hashcat_simulation.HashcatSimulator()
    
    # Test passwords
    test_passwords = [
        "password123",
        "Barclays2023",
        "P@ssw0rd123",
        "S3cur3B@nk1ng2023!",
        "Tr0ub4dor&3"
    ]
    
    for pwd in test_passwords:
        print(f"\nAnalyzing password: {pwd}")
        print("-" * 40)
        
        # Estimate crack times
        for attack_type in ['brute_force', 'dictionary', 'targeted']:
            time_estimate = simulator.estimate_crack_time(
                pwd, 'sha256', 'gpu_mid', attack_type)
            print(f"  - {attack_type}: {time_estimate}")
        
        # Simulate attack
        simulator.simulate_attack(pwd, 'dictionary')
    
    # Generate visualizations
    simulator.visualize_attack_comparison("S3cur3B@nk1ng2023!")
    print("\nVisualizations saved as 'attack_comparison.png' and 'hash_comparison.png'")

def main():
    parser = argparse.ArgumentParser(description="Barclays Password Strength Analyzer")
    parser.add_argument("--generate-data", action="store_true", help="Generate password dataset")
    parser.add_argument("--train-model", action="store_true", help="Train password strength model")
    parser.add_argument("--run-app", action="store_true", help="Run web application")
    parser.add_argument("--run-api", action="store_true", help="Run API server")
    parser.add_argument("--run-simulation", action="store_true", help="Run Hashcat simulation")
    parser.add_argument("--run-all", action="store_true", help="Run all components")
    
    args = parser.parse_args()
    
    # Print banner
    print("\n" + "=" * 80)
    print("Barclays Password Strength Analyzer")
    print("Machine Learning-based Security for Banking Systems")
    print("=" * 80 + "\n")
    
    # Check dependencies
    if not check_dependencies():
        return
    
    # If no arguments provided, show help
    if not any(vars(args).values()):
        parser.print_help()
        return
    
    # Run components based on arguments
    if args.run_all or args.generate_data:
        generate_dataset()
    
    if args.run_all or args.train_model:
        train_model()
    
    if args.run_all or args.run_simulation:
        run_hashcat_simulation()
    
    if args.run_all or args.run_api:
        run_api_server()
    
    if args.run_all or args.run_app:
        run_web_app()

if __name__ == "__main__":
    main()