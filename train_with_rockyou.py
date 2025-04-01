#!/usr/bin/env python
"""
Train the password strength model using the RockYou dataset.

This script demonstrates how to use the RockYou dataset to train the password strength model.
It downloads the RockYou dataset, generates a training dataset that includes passwords from
RockYou, and trains the model using this dataset.
"""

import os
import argparse
import time
from generate_dataset import generate_dataset
from train_models import load_data, analyze_features, train_and_evaluate_models, hyperparameter_tuning, save_best_model
from password_strength_analyzer import PasswordStrengthAnalyzer
from rockyou_utils import download_rockyou_dataset, load_rockyou_passwords


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Train password strength model using RockYou dataset")
    parser.add_argument("--output", type=str, default="data/password_dataset.csv",
                        help="Path to save the generated dataset")
    parser.add_argument("--samples", type=int, default=5000,
                        help="Total number of passwords to include in the dataset")
    parser.add_argument("--rockyou-ratio", type=float, default=0.5,
                        help="Ratio of passwords to take from RockYou dataset (0.0-1.0)")
    parser.add_argument("--model-dir", type=str, default="models",
                        help="Directory to save the trained model")
    parser.add_argument("--no-tuning", action="store_true",
                        help="Skip hyperparameter tuning (faster training)")
    return parser.parse_args()


def save_best_model(results, best_model_name, model_dir="models"):
    """Save the best model to a file."""
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, f"{best_model_name.lower().replace(' ', '_')}_model.joblib")
    import joblib
    joblib.dump(results[best_model_name]['model'], model_path)
    print(f"\nBest model saved to {model_path}")
    return model_path


def main():
    """Main function to train the password strength model using RockYou dataset."""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Create necessary directories
    os.makedirs("data", exist_ok=True)
    os.makedirs(args.model_dir, exist_ok=True)
    os.makedirs("plots", exist_ok=True)
    
    # Download RockYou dataset if it doesn't exist
    print("Checking RockYou dataset...")
    download_rockyou_dataset()
    
    # Generate dataset with RockYou passwords
    print(f"\nGenerating dataset with {args.samples} passwords (RockYou ratio: {args.rockyou_ratio})...")
    dataset = generate_dataset(
        output_file=args.output,
        n_samples=args.samples,
        include_rockyou=True,
        rockyou_ratio=args.rockyou_ratio
    )
    
    # Split dataset into train and test sets
    train_file = "data/train_dataset.csv"
    test_file = "data/test_dataset.csv"
    
    # Check if train/test files already exist
    if not os.path.exists(train_file) or not os.path.exists(test_file):
        print("Splitting dataset into train and test sets...")
        from sklearn.model_selection import train_test_split
        train_df, test_df = train_test_split(dataset, test_size=0.2, random_state=42)
        train_df.to_csv(train_file, index=False)
        test_df.to_csv(test_file, index=False)
    
    # Load data
    print("\nLoading data...")
    (X_train, y_train, X_test, y_test), (train_df, test_df) = load_data(train_file, test_file)
    
    if X_train is None:
        print("Failed to load data. Exiting.")
        return
    
    print(f"Training set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"Test set: {X_test.shape[0]} samples, {X_test.shape[1]} features")
    
    # Analyze features
    print("\nAnalyzing features...")
    feature_scores = analyze_features(X_train, y_train)
    
    # Train and evaluate models
    print("\nTraining and evaluating models...")
    results = train_and_evaluate_models(X_train, y_train, X_test, y_test)
    
    # Find best model
    best_model_name = max(results.items(), key=lambda x: x[1]['accuracy'])[0]
    print(f"\nBest model: {best_model_name} with accuracy {results[best_model_name]['accuracy']:.4f}")
    
    # Perform hyperparameter tuning on best model if requested
    if not args.no_tuning:
        print("\nPerforming hyperparameter tuning...")
        best_model = hyperparameter_tuning(X_train, y_train, X_test, y_test, best_model_name, results)
        # Save the tuned model
        model_path = os.path.join(args.model_dir, f"{best_model_name.lower().replace(' ', '_')}_model.joblib")
        import joblib
        joblib.dump(best_model, model_path)
        print(f"\nTuned model saved to {model_path}")
    else:
        # Save the best model without tuning
        model_path = save_best_model(results, best_model_name, args.model_dir)
    
    print("\nModel training complete!")
    print(f"Dataset saved to {args.output}")
    print(f"Best model: {best_model_name}")
    print(f"Model saved to {model_path}")
    
    # Initialize the password strength analyzer with the trained model
    analyzer = PasswordStrengthAnalyzer(model_path=model_path)
    print("\nPassword Strength Analyzer initialized with the trained model.")
    print("You can now use the analyzer to evaluate password strength.")


if __name__ == "__main__":
    main()