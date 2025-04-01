import subprocess
import os
import platform
import re
import time
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from password_strength_analyzer import PasswordStrengthAnalyzer

class HashcatSimulator:
    """Simulates password cracking attempts using Hashcat benchmarks.
    
    This class provides more accurate time-to-crack estimates by using
    real-world benchmarking data from Hashcat, a popular password cracking tool.
    """
    
    def __init__(self, hashcat_path=None, model_path=None):
        """Initialize the Hashcat simulator.
        
        Args:
            hashcat_path: Path to hashcat executable (optional)
            model_path: Path to a pre-trained password strength model (optional)
        """
        self.hashcat_path = hashcat_path
        self.benchmark_data = self._load_benchmark_data()
        
        # Default cracking speeds (hashes per second) if no benchmark data available
        self.default_speeds = {
            'brute_force': 10_000_000_000,  # 10 billion/s
            'dictionary': 15_000_000_000,   # 15 billion/s
            'targeted': 5_000_000_000       # 5 billion/s
        }
        
        # Initialize the password strength analyzer with a trained model if available
        if model_path and os.path.exists(model_path):
            self.analyzer = PasswordStrengthAnalyzer(model_path=model_path)
        else:
            # Try to find a trained model in the models directory
            model_files = [f for f in os.listdir('models') if f.endswith('_model.joblib')] if os.path.exists('models') else []
            if model_files:
                self.analyzer = PasswordStrengthAnalyzer(model_path=os.path.join('models', model_files[0]))
            else:
                # Create a simple analyzer without a pre-trained model
                self.analyzer = PasswordStrengthAnalyzer()
    
    def _load_benchmark_data(self):
        """Load benchmark data from file or use defaults."""
        benchmark_file = 'hashcat_benchmarks.json'
        
        if os.path.exists(benchmark_file):
            try:
                with open(benchmark_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading benchmark data: {e}")
                return self._generate_default_benchmarks()
        else:
            return self._generate_default_benchmarks()
    
    def _generate_default_benchmarks(self):
        """Generate default benchmark data based on common hardware."""
        # These values represent approximate hash rates for different hardware
        # configurations and hash types
        return {
            'md5': {
                'cpu': 1_000_000_000,       # 1 billion/s
                'gpu_mid': 15_000_000_000,  # 15 billion/s
                'gpu_high': 50_000_000_000  # 50 billion/s
            },
            'sha1': {
                'cpu': 500_000_000,         # 500 million/s
                'gpu_mid': 5_000_000_000,   # 5 billion/s
                'gpu_high': 15_000_000_000  # 15 billion/s
            },
            'sha256': {
                'cpu': 200_000_000,         # 200 million/s
                'gpu_mid': 2_000_000_000,   # 2 billion/s
                'gpu_high': 7_000_000_000   # 7 billion/s
            },
            'sha512': {
                'cpu': 100_000_000,         # 100 million/s
                'gpu_mid': 1_000_000_000,   # 1 billion/s
                'gpu_high': 3_000_000_000   # 3 billion/s
            },
            'bcrypt': {
                'cpu': 20_000,              # 20 thousand/s
                'gpu_mid': 100_000,         # 100 thousand/s
                'gpu_high': 300_000         # 300 thousand/s
            },
            'ntlm': {
                'cpu': 2_000_000_000,       # 2 billion/s
                'gpu_mid': 25_000_000_000,  # 25 billion/s
                'gpu_high': 80_000_000_000  # 80 billion/s
            }
        }
    
    def run_hashcat_benchmark(self):
        """Run hashcat benchmark and parse results.
        
        Note: This requires hashcat to be installed on the system.
        """
        if not self.hashcat_path:
            # Try to find hashcat in common locations
            if platform.system() == 'Windows':
                possible_paths = [
                    'C:\\hashcat\\hashcat.exe',
                    'C:\\Program Files\\hashcat\\hashcat.exe',
                    'hashcat.exe'
                ]
            else:  # Linux/Mac
                possible_paths = [
                    '/usr/bin/hashcat',
                    '/usr/local/bin/hashcat',
                    'hashcat'
                ]
            
            for path in possible_paths:
                if os.path.exists(path) or self._check_command_exists(path):
                    self.hashcat_path = path
                    break
        
        if not self.hashcat_path:
            print("Hashcat not found. Using default benchmark values.")
            return False
        
        try:
            # Run hashcat benchmark
            print("Running hashcat benchmark. This may take a few minutes...")
            cmd = [self.hashcat_path, '--benchmark', '--machine-readable']
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Parse benchmark results
            output = stdout.decode('utf-8')
            benchmarks = {}
            
            # Example parsing logic (would need to be adapted to actual hashcat output format)
            for line in output.split('\n'):
                if 'SPEED' in line:
                    parts = line.split(',')
                    hash_type = parts[1]
                    speed = float(parts[3])
                    benchmarks[hash_type] = speed
            
            # Save benchmark results
            with open('hashcat_benchmarks.json', 'w') as f:
                json.dump(benchmarks, f)
            
            self.benchmark_data = benchmarks
            return True
        
        except Exception as e:
            print(f"Error running hashcat benchmark: {e}")
            return False
    
    def _check_command_exists(self, cmd):
        """Check if a command exists in the system path."""
        try:
            subprocess.run([cmd, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except:
            return False
    
    def estimate_crack_time(self, password, hash_type='sha256', hardware='gpu_mid', attack_type='brute_force'):
        """Estimate time to crack a password using benchmark data.
        
        Args:
            password: The password to analyze
            hash_type: Hash algorithm (md5, sha1, sha256, sha512, bcrypt, ntlm)
            hardware: Hardware type (cpu, gpu_mid, gpu_high)
            attack_type: Attack method (brute_force, dictionary, targeted)
            
        Returns:
            Dictionary with estimated crack times
        """
        # Calculate character space
        char_space = 0
        if any(c.islower() for c in password):
            char_space += 26  # lowercase letters
        if any(c.isupper() for c in password):
            char_space += 26  # uppercase letters
        if any(c.isdigit() for c in password):
            char_space += 10  # digits
        if any(not c.isalnum() for c in password):
            char_space += 33  # special characters
        
        # Ensure minimum character space
        char_space = max(char_space, 26)
        
        # Calculate possible combinations
        combinations = char_space ** len(password)
        
        # Get cracking speed from benchmark data
        if hash_type in self.benchmark_data and hardware in self.benchmark_data[hash_type]:
            speed = self.benchmark_data[hash_type][hardware]
        else:
            # Use default speed if benchmark data not available
            speed = self.default_speeds[attack_type]
        
        # Apply attack-specific modifiers
        if attack_type == 'dictionary':
            # Dictionary attacks are faster but depend on password complexity
            if self._is_common_pattern(password):
                combinations = min(combinations, 1_000_000)  # Limit to dictionary size
        elif attack_type == 'targeted':
            # Targeted attacks use information about the user
            if self._is_common_pattern(password):
                combinations = min(combinations, 100_000)  # Even smaller search space
        
        # Calculate time in seconds
        seconds = combinations / speed
        
        # Format time
        return self._format_time(seconds)
    
    def _is_common_pattern(self, password):
        """Check if password contains common patterns."""
        common_patterns = [
            r'\b(password|pass|pwd)\b',  # Common password words
            r'\b(123|abc|qwerty)\b',     # Common sequences
            r'\b(admin|root|user)\b',    # Common usernames
            r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b',  # Months
            r'\b(barclays|bank|secure|login)\b',  # Banking related
            r'\b(19\d{2}|20\d{2})\b'    # Years
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                return True
        
        return False
    
    def _format_time(self, seconds):
        """Format time in a human-readable way."""
        if seconds < 1:
            return "less than a second"
        elif seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        elif seconds < 31536000*100:
            return f"{seconds/31536000:.2f} years"
        else:
            return "centuries"

    def simulate_attack(self, password, attack_type='brute_force', verbose=True):
        """Simulate a password cracking attack.
        
        Args:
            password: The password to attack
            attack_type: Type of attack (brute_force, dictionary, targeted)
            verbose: Whether to print progress
            
        Returns:
            Dictionary with attack results
        """
        start_time = time.time()
        
        # Determine attack parameters based on type
        if attack_type == 'brute_force':
            # Brute force tries all possible combinations
            max_attempts = 1_000_000  # Limit for simulation
            success_chance = 0.5  # 50% chance of success within max_attempts
        elif attack_type == 'dictionary':
            # Dictionary attack uses common passwords
            max_attempts = 100_000
            success_chance = 0.8 if self._is_common_pattern(password) else 0.3
        elif attack_type == 'targeted':
            # Targeted attack uses information about the user
            max_attempts = 10_000
            success_chance = 0.9 if self._is_common_pattern(password) else 0.2
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        # Simulate attack progress
        if verbose:
            print(f"\nSimulating {attack_type} attack on password...")
        
        # Extract features from the password
        features = self.analyzer._extract_features(password)
        
        # Add the missing 'in_rockyou' feature (set to 0 by default since we don't check)
        # This ensures we have the same number of features as the trained model expects
        features_with_rockyou = np.append(features, [[0]], axis=1)  # Add in_rockyou=0 as the 12th feature
        
        # Predict strength using the complete feature set
        strength_score = int(self.analyzer.model.predict(features_with_rockyou)[0])
        
        # Adjust success probability based on password strength
        success_chance *= (1 - (strength_score / 5))
        
        # Determine if attack will succeed within max_attempts
        will_succeed = np.random.random() < success_chance
        
        # Simulate attack progress
        attempts = 0
        found = False
        
        # Number of progress updates to show
        progress_steps = 10
        
        for step in range(progress_steps + 1):
            # Calculate current attempts
            if will_succeed:
                current_attempts = int((step / progress_steps) * max_attempts)
            else:
                current_attempts = int((step / progress_steps) * max_attempts * 0.9)  # Never reach max if won't succeed
            
            # Update attempts
            attempts = current_attempts
            
            # Check if password is found
            if will_succeed and step == progress_steps:
                found = True
            
            # Print progress
            if verbose and step < progress_steps:
                progress = '#' * step + ' ' * (progress_steps - step)
                print(f"[{progress}] Attempts: {attempts:,} / {max_attempts:,}", end='\r')
                time.sleep(0.2)  # Simulate processing time
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        if verbose:
            if found:
                print(f"\n✓ Password cracked after {attempts:,} attempts and {elapsed_time:.2f} seconds")
            else:
                print(f"\n✗ Attack failed after {attempts:,} attempts and {elapsed_time:.2f} seconds")
        
        # Return results
        return {
            'success': found,
            'attempts': attempts,
            'max_attempts': max_attempts,
            'elapsed_time': elapsed_time,
            'attack_type': attack_type,
            'password_strength': strength_score
        }

    def compare_hash_algorithms(self, password):
        """Compare crack times for different hash algorithms.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary with crack times for different algorithms
        """
        hash_types = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'ntlm']
        hardware_types = ['cpu', 'gpu_mid', 'gpu_high']
        
        results = {}
        for hash_type in hash_types:
            results[hash_type] = {}
            for hardware in hardware_types:
                results[hash_type][hardware] = self.estimate_crack_time(
                    password, hash_type, hardware, 'brute_force')
        
        return results

    def visualize_attack_comparison(self, password):
        """Visualize attack comparison for a password.
        
        Args:
            password: The password to analyze
        """
        # Run different attack simulations
        attack_types = ['brute_force', 'dictionary', 'targeted']
        results = []
        
        for attack_type in attack_types:
            result = self.simulate_attack(password, attack_type, verbose=False)
            results.append(result)
        
        # Create DataFrame for visualization
        df = pd.DataFrame(results)
        
        # Create figure with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Plot attempts by attack type
        sns.barplot(x='attack_type', y='attempts', data=df, ax=ax1)
        ax1.set_title('Attack Attempts by Type')
        ax1.set_ylabel('Number of Attempts')
        ax1.set_xlabel('Attack Type')
        
        # Plot success by attack type
        success_data = df[['attack_type', 'success']].copy()
        success_data['success'] = success_data['success'].astype(int)
        sns.barplot(x='attack_type', y='success', data=success_data, ax=ax2)
        ax2.set_title('Attack Success by Type')
        ax2.set_ylabel('Success (0=Failed, 1=Succeeded)')
        ax2.set_xlabel('Attack Type')
        ax2.set_ylim(0, 1)
        
        plt.tight_layout()
        plt.savefig('attack_comparison.png')
        plt.close()
        
        # Also compare hash algorithms
        hash_results = self.compare_hash_algorithms(password)
        
        # Create data for heatmap
        hash_types = list(hash_results.keys())
        hardware_types = list(hash_results[hash_types[0]].keys())
        
        # Convert time strings to numeric values (log scale of seconds)
        def time_to_log_seconds(time_str):
            if 'less than a second' in time_str:
                return 0
            elif 'seconds' in time_str:
                return np.log10(float(time_str.split()[0]))
            elif 'minutes' in time_str:
                return np.log10(float(time_str.split()[0]) * 60)
            elif 'hours' in time_str:
                return np.log10(float(time_str.split()[0]) * 3600)
            elif 'days' in time_str:
                return np.log10(float(time_str.split()[0]) * 86400)
            elif 'years' in time_str:
                return np.log10(float(time_str.split()[0]) * 31536000)
            else:  # centuries
                return np.log10(31536000 * 100)
        
        # Create heatmap data
        heatmap_data = np.zeros((len(hash_types), len(hardware_types)))
        for i, hash_type in enumerate(hash_types):
            for j, hardware in enumerate(hardware_types):
                heatmap_data[i, j] = time_to_log_seconds(hash_results[hash_type][hardware])
        
        # Create heatmap
        plt.figure(figsize=(12, 8))
        sns.heatmap(
            heatmap_data,
            annot=True,
            fmt=".1f",
            xticklabels=hardware_types,
            yticklabels=hash_types,
            cmap="YlOrRd"
        )
        plt.title(f'Log10(Seconds) to Crack Password with Different Hash Algorithms and Hardware')
        plt.xlabel('Hardware Type')
        plt.ylabel('Hash Algorithm')
        plt.tight_layout()
        plt.savefig('hash_comparison.png')
        plt.close()
        
        return {
            'attack_results': results,
            'hash_results': hash_results
        }


# Example usage
if __name__ == "__main__":
    # Create simulator
    simulator = HashcatSimulator()
    
    # Try to run hashcat benchmark if available
    simulator.run_hashcat_benchmark()
    
    # Test passwords
    test_passwords = [
        "password123",
        "Barclays2023",
        "P@ssw0rd123",
        "S3cur3B@nk1ng2023!",
        "Tr0ub4dor&3"
    ]
    
    print("\n===== Password Cracking Simulation =====\n")
    
    for pwd in test_passwords:
        print(f"\n\nAnalyzing password: {pwd}")
        print("-" * 40)
        
        # Estimate crack times for different attack types
        print("\nEstimated crack times:")
        for attack_type in ['brute_force', 'dictionary', 'targeted']:
            time_estimate = simulator.estimate_crack_time(
                pwd, 'sha256', 'gpu_mid', attack_type)
            print(f"  - {attack_type}: {time_estimate}")
        
        # Simulate an attack
        most_effective_attack = 'brute_force'
        if simulator._is_common_pattern(pwd):
            most_effective_attack = 'dictionary'
        
        print(f"\nSimulating most effective attack ({most_effective_attack}):")
        result = simulator.simulate_attack(pwd, most_effective_attack)
        
        # Compare hash algorithms
        print("\nComparing hash algorithms (GPU mid-range):")
        hash_comparison = simulator.compare_hash_algorithms(pwd)
        for hash_type, results in hash_comparison.items():
            print(f"  - {hash_type}: {results['gpu_mid']}")
    
    # Visualize attack comparison for a strong password
    print("\n\nGenerating visualization for 'S3cur3B@nk1ng2023!'...")
    simulator.visualize_attack_comparison("S3cur3B@nk1ng2023!")
    print("Visualizations saved as 'attack_comparison.png' and 'hash_comparison.png'")