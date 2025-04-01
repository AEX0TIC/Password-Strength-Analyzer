import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
from sklearn.inspection import permutation_importance
import warnings

warnings.filterwarnings('ignore')


def load_data(train_file="data/train_dataset.csv", test_file="data/test_dataset.csv"):
    """Load training and test datasets."""
    if not os.path.exists(train_file) or not os.path.exists(test_file):
        print("Dataset files not found. Please run generate_dataset.py first.")
        return None, None
    
    train_df = pd.read_csv(train_file)
    test_df = pd.read_csv(test_file)
    
    # Remove the actual password from the features
    X_train = train_df.drop(['password', 'strength'], axis=1)
    y_train = train_df['strength']
    
    X_test = test_df.drop(['password', 'strength'], axis=1)
    y_test = test_df['strength']
    
    return (X_train, y_train, X_test, y_test), (train_df, test_df)


def analyze_features(X_train, y_train):
    """Analyze feature importance and correlations."""
    # Create output directory for plots
    os.makedirs("plots", exist_ok=True)
    
    # Feature correlation analysis
    plt.figure(figsize=(12, 10))
    correlation_matrix = X_train.corr()
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', fmt=".2f")
    plt.title('Feature Correlation Matrix')
    plt.tight_layout()
    plt.savefig('plots/feature_correlation.png')
    
    # Feature importance using ANOVA F-value
    selector = SelectKBest(f_classif, k='all')
    selector.fit(X_train, y_train)
    
    # Plot feature importance
    plt.figure(figsize=(12, 8))
    feature_scores = pd.DataFrame({
        'Feature': X_train.columns,
        'Score': selector.scores_
    })
    feature_scores = feature_scores.sort_values('Score', ascending=False)
    
    sns.barplot(x='Score', y='Feature', data=feature_scores)
    plt.title('Feature Importance (ANOVA F-value)')
    plt.tight_layout()
    plt.savefig('plots/feature_importance.png')
    
    print("\nTop 5 most important features:")
    print(feature_scores.head(5))
    
    return feature_scores


def train_and_evaluate_models(X_train, y_train, X_test, y_test):
    """Train and evaluate multiple ML models for password strength prediction."""
    # Define models to evaluate
    models = {
        'Random Forest': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', RandomForestClassifier(random_state=42))
        ]),
        'Gradient Boosting': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', GradientBoostingClassifier(random_state=42))
        ]),
        'Neural Network': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', MLPClassifier(random_state=42, max_iter=1000))
        ]),
        'SVM': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', SVC(random_state=42))
        ])
    }
    
    # Train and evaluate each model
    results = {}
    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)
        
        # Evaluate on test set
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"{name} Test Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Store results
        results[name] = {
            'model': model,
            'accuracy': accuracy,
            'predictions': y_pred
        }
    
    return results


def hyperparameter_tuning(X_train, y_train, X_test, y_test, best_model_name, results):
    """Perform hyperparameter tuning on the best model."""
    print(f"\nPerforming hyperparameter tuning for {best_model_name}...")
    
    if best_model_name == 'Random Forest':
        param_grid = {
            'classifier__n_estimators': [50, 100, 200],
            'classifier__max_depth': [None, 10, 20, 30],
            'classifier__min_samples_split': [2, 5, 10],
            'classifier__min_samples_leaf': [1, 2, 4]
        }
    elif best_model_name == 'Gradient Boosting':
        param_grid = {
            'classifier__n_estimators': [50, 100, 200],
            'classifier__learning_rate': [0.01, 0.1, 0.2],
            'classifier__max_depth': [3, 5, 7],
            'classifier__min_samples_split': [2, 5, 10]
        }
    elif best_model_name == 'Neural Network':
        param_grid = {
            'classifier__hidden_layer_sizes': [(50,), (100,), (50, 50), (100, 50)],
            'classifier__activation': ['relu', 'tanh'],
            'classifier__alpha': [0.0001, 0.001, 0.01],
            'classifier__learning_rate': ['constant', 'adaptive']
        }
    elif best_model_name == 'SVM':
        param_grid = {
            'classifier__C': [0.1, 1, 10, 100],
            'classifier__gamma': ['scale', 'auto', 0.1, 0.01],
            'classifier__kernel': ['rbf', 'poly', 'sigmoid']
        }
    else:
        print(f"No hyperparameter grid defined for {best_model_name}")
        return results[best_model_name]['model']
    
    # Create grid search
    grid_search = GridSearchCV(
        results[best_model_name]['model'],
        param_grid,
        cv=5,
        scoring='accuracy',
        n_jobs=-1
    )
    
    # Fit grid search
    grid_search.fit(X_train, y_train)
    
    # Get best model
    best_model = grid_search.best_estimator_
    
    # Evaluate best model
    y_pred = best_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nBest parameters: {grid_search.best_params_}")
    print(f"Best model accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Plot confusion matrix
    plt.figure(figsize=(10, 8))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title(f'Confusion Matrix - Tuned {best_model_name}')
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.savefig(f'plots/confusion_matrix_{best_model_name.lower().replace(" ", "_")}.png')
    
    return best_model


def analyze_model_performance(best_model, X_train, y_train, X_test, y_test, feature_names):
    """Analyze the performance of the best model in detail."""
    # Get feature importance for the best model (if applicable)
    if hasattr(best_model[-1], 'feature_importances_'):
        # For tree-based models
        importances = best_model[-1].feature_importances_
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(12, 8))
        plt.title('Feature Importances')
        plt.bar(range(X_train.shape[1]), importances[indices], align='center')
        plt.xticks(range(X_train.shape[1]), [feature_names[i] for i in indices], rotation=90)
        plt.tight_layout()
        plt.savefig('plots/best_model_feature_importance.png')
        
        print("\nTop 5 most important features:")
        for i in range(5):
            print(f"{feature_names[indices[i]]}: {importances[indices[i]]:.4f}")
    else:
        # For models without built-in feature importance, use permutation importance
        print("\nCalculating permutation feature importance...")
        perm_importance = permutation_importance(best_model, X_test, y_test, n_repeats=10, random_state=42)
        
        feature_importance = pd.DataFrame({
            'Feature': feature_names,
            'Importance': perm_importance.importances_mean
        }).sort_values('Importance', ascending=False)
        
        plt.figure(figsize=(12, 8))
        sns.barplot(x='Importance', y='Feature', data=feature_importance)
        plt.title('Permutation Feature Importance')
        plt.tight_layout()
        plt.savefig('plots/permutation_feature_importance.png')
        
        print("\nTop 5 most important features (permutation importance):")
        print(feature_importance.head(5))
    
    # Analyze model errors
    y_pred = best_model.predict(X_test)
    errors = y_test != y_pred
    
    error_analysis = pd.DataFrame({
        'True': y_test[errors],
        'Predicted': y_pred[errors],
        'Error': y_test[errors] - y_pred[errors]
    })
    
    print("\nError Analysis:")
    print(f"Total errors: {errors.sum()} out of {len(y_test)} ({errors.sum()/len(y_test)*100:.2f}%)")
    print("\nError distribution:")
    print(error_analysis['Error'].value_counts())
    
    # Plot error distribution
    plt.figure(figsize=(10, 6))
    sns.countplot(x='Error', data=error_analysis)
    plt.title('Error Distribution')
    plt.xlabel('Error (True - Predicted)')
    plt.ylabel('Count')
    plt.savefig('plots/error_distribution.png')
    
    return error_analysis


def save_model(model, model_name, output_dir="models"):
    """Save the trained model to a file."""
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, f"{model_name.lower().replace(' ', '_')}_model.joblib")
    joblib.dump(model, model_path)
    print(f"\nModel saved to {model_path}")
    return model_path


def main():
    # Create necessary directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    os.makedirs("plots", exist_ok=True)
    
    # Check if dataset exists, if not, generate it
    if not os.path.exists("data/train_dataset.csv") or not os.path.exists("data/test_dataset.csv"):
        print("Dataset not found. Running generate_dataset.py...")
        import generate_dataset
        generate_dataset.generate_dataset("data/password_dataset.csv", n_samples=5000)
    
    # Load data
    print("\nLoading data...")
    (X_train, y_train, X_test, y_test), (train_df, test_df) = load_data()
    
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
    
    # Perform hyperparameter tuning on best model
    best_model = hyperparameter_tuning(X_train, y_train, X_test, y_test, best_model_name, results)
    
    # Analyze model performance
    print("\nAnalyzing model performance...")
    analyze_model_performance(best_model, X_train, y_train, X_test, y_test, X_train.columns)
    
    # Save best model
    model_path = save_model(best_model, best_model_name)
    
    print(f"\nModel training complete. Best model: {best_model_name}")
    print(f"Model saved to {model_path}")
    
    return best_model, model_path


if __name__ == "__main__":
    main()