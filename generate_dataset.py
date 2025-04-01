import pandas as pd
import numpy as np
import random
import string
import re
import hashlib
import os
import time
from sklearn.model_selection import train_test_split
from rockyou_utils import load_rockyou_passwords, get_common_password_dict


# Global variable to store common passwords dictionary
common_passwords_dict = None

def is_in_rockyou(password):
    """Check if a password is in the RockYou dataset."""
    try:
        global common_passwords_dict
        
        # Initialize the dictionary if it hasn't been loaded yet
        if common_passwords_dict is None:
            common_passwords_dict = get_common_password_dict(top_n=100000)
        
        return 1 if password in common_passwords_dict else 0
    except Exception as e:
        # If there's an error accessing the RockYou dataset, return 0
        print(f"Warning: Error checking if password is in RockYou: {str(e)}")
        return 0


def generate_common_passwords(n=1000):
    """Generate common weak passwords from patterns frequently used."""
    common_passwords = []
    
    # Common base words
    base_words = [
        "password", "admin", "welcome", "123456", "qwerty", "letmein", "monkey", 
        "dragon", "baseball", "football", "master", "michael", "superman", "batman",
        "trustno", "access", "shadow", "mustang", "soccer", "hockey", "killer", "george",
        "andrew", "charlie", "thomas", "robert", "matthew", "jordan", "daniel", "barclays",
        "bank", "secure", "login", "user", "customer", "account", "money", "finance", "credit",
        "debit", "card", "pin", "atm", "branch", "online", "mobile", "app", "banking"
    ]
    
    # Years, months, seasons
    years = [str(year) for year in range(1990, 2024)]
    months = ["january", "february", "march", "april", "may", "june", "july", 
              "august", "september", "october", "november", "december",
              "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
    seasons = ["spring", "summer", "autumn", "winter", "fall"]
    
    # Common number patterns
    number_patterns = ["123", "1234", "12345", "123456", "654321", "54321", "4321", "321",
                      "111", "222", "333", "444", "555", "666", "777", "888", "999", "000"]
    
    # Generate passwords
    for _ in range(n):
        pattern_type = random.randint(1, 5)
        
        if pattern_type == 1:
            # Word + number
            pwd = random.choice(base_words) + random.choice(years)
        elif pattern_type == 2:
            # Word + special char + number
            pwd = random.choice(base_words) + random.choice(["!", "@", "#", "$", "%"]) + random.choice(number_patterns)
        elif pattern_type == 3:
            # Season/month + year
            pwd = random.choice(months + seasons) + random.choice(years)
        elif pattern_type == 4:
            # Simple word with first letter capitalized + number
            word = random.choice(base_words)
            pwd = word[0].upper() + word[1:] + random.choice(number_patterns)
        else:
            # Banking related term + year
            banking_terms = ["barclays", "bank", "secure", "login", "account", "money", "finance"]
            pwd = random.choice(banking_terms) + random.choice(years)
        
        # Sometimes add a simple transformation
        if random.random() < 0.3:
            # Replace some letters with numbers (leet speak)
            pwd = pwd.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
        
        common_passwords.append(pwd)
    
    return common_passwords


def generate_strong_passwords(n=1000):
    """Generate strong passwords using various techniques."""
    strong_passwords = []
    
    for _ in range(n):
        length = random.randint(12, 24)  # Strong passwords are longer
        
        # Decide on password generation strategy
        strategy = random.randint(1, 4)
        
        if strategy == 1:
            # Completely random with all character types
            chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
            pwd = ''.join(random.choice(chars) for _ in range(length))
        
        elif strategy == 2:
            # Passphrase-like (multiple words with separators and transformations)
            words = ["secure", "protect", "defend", "shield", "guard", "safety", "privacy", 
                    "encrypt", "firewall", "fortress", "bastion", "citadel", "vault", "safe", 
                    "lock", "key", "code", "cipher", "crypto", "hidden", "secret", "private"]
            
            # Select 3-4 random words
            selected_words = random.sample(words, random.randint(3, 4))
            
            # Apply transformations and add separators
            transformed_words = []
            for word in selected_words:
                # Randomly apply transformations
                if random.random() < 0.5:
                    # Capitalize
                    word = word.capitalize()
                if random.random() < 0.3:
                    # Replace with leet speak
                    word = word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
                transformed_words.append(word)
            
            # Join with random separators
            separators = [".", "_", "-", "!", "@", "#", "$", "%", "&", "*"]
            pwd = random.choice(separators).join(transformed_words)
            
            # Add some numbers at the end
            pwd += str(random.randint(100, 9999))
        
        elif strategy == 3:
            # Banking security focused password
            # Start with a strong base
            base = ''.join(random.choice(string.ascii_letters) for _ in range(8))
            
            # Ensure it has uppercase, lowercase, digit, and special char
            pwd = base
            pwd += random.choice(string.ascii_uppercase)
            pwd += random.choice(string.ascii_lowercase)
            pwd += random.choice(string.digits)
            pwd += random.choice(string.punctuation)
            
            # Shuffle the password
            pwd_list = list(pwd)
            random.shuffle(pwd_list)
            pwd = ''.join(pwd_list)
            
            # Add more random chars if needed to reach desired length
            while len(pwd) < length:
                pwd += random.choice(string.ascii_letters + string.digits + string.punctuation)
        
        else:
            # Pattern-based but strong
            # Create a pattern that looks memorable but is actually strong
            pattern_parts = []
            
            # Add a word-like part with transformations
            word_base = random.choice(["Secure", "Protect", "Shield", "Guard", "Bank", "Finance"])
            transformed_word = ""
            for char in word_base:
                if random.random() < 0.4:
                    # Transform to leet or add special char
                    if char.lower() == 'a': transformed_word += "@"
                    elif char.lower() == 'e': transformed_word += "3"
                    elif char.lower() == 'i': transformed_word += "!"
                    elif char.lower() == 'o': transformed_word += "0"
                    elif char.lower() == 's': transformed_word += "$"
                    else: transformed_word += char
                else:
                    transformed_word += char
            
            pattern_parts.append(transformed_word)
            
            # Add a number part
            pattern_parts.append(str(random.randint(1000, 9999)))
            
            # Add a special char sequence
            special_seq = ''.join(random.choice(string.punctuation) for _ in range(random.randint(2, 4)))
            pattern_parts.append(special_seq)
            
            # Shuffle the parts and join
            random.shuffle(pattern_parts)
            pwd = ''.join(pattern_parts)
            
            # Add more random chars if needed
            while len(pwd) < length:
                pwd += random.choice(string.ascii_letters + string.digits + string.punctuation)
        
        strong_passwords.append(pwd)
    
    return strong_passwords


def calculate_password_strength(password):
    """Calculate password strength on a scale of 0-4."""
    # Initialize score
    score = 0
    
    # Length check
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if len(password) >= 16: score += 1
    
    # Character composition
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[0-9]', password): score += 1
    if re.search(r'[^A-Za-z0-9]', password): score += 1
    
    # Deduct for common patterns
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
            score -= 1
            break
    
    # Check for sequential characters
    for i in range(len(password)-2):
        if (ord(password[i]) + 1 == ord(password[i+1]) and 
            ord(password[i+1]) + 1 == ord(password[i+2])) or \
           (ord(password[i]) - 1 == ord(password[i+1]) and 
            ord(password[i+1]) - 1 == ord(password[i+2])):
            score -= 1
            break
    
    # Check for repeated characters
    for i in range(len(password)-2):
        if password[i] == password[i+1] == password[i+2]:
            score -= 1
            break
    
    # Calculate entropy as additional factor
    char_freq = {}
    for char in password:
        char_freq[char] = char_freq.get(char, 0) + 1
    entropy = -sum((freq/len(password)) * np.log2(freq/len(password)) for freq in char_freq.values())
    
    # Adjust score based on entropy
    if entropy > 4.0: score += 1
    
    # Check if password is in RockYou dataset (major penalty)
    if is_in_rockyou(password):
        score -= 2  # Significant penalty for being in a known breach
    
    # Ensure score is within 0-4 range
    return max(0, min(4, score))


def generate_dataset(output_file, n_samples=5000, include_rockyou=True, rockyou_ratio=0.3):
    """Generate a comprehensive password dataset with strength labels.
    
    Args:
        output_file: Path to save the dataset
        n_samples: Total number of passwords to generate
        include_rockyou: Whether to include passwords from the RockYou dataset
        rockyou_ratio: Ratio of passwords to take from RockYou (if include_rockyou is True)
    """
    # Calculate how many passwords to generate vs. take from RockYou
    n_rockyou = int(n_samples * rockyou_ratio) if include_rockyou else 0
    n_generated = n_samples - n_rockyou
    
    # Generate synthetic passwords
    print("Generating weak passwords...")
    weak_passwords = generate_common_passwords(n=n_generated//2)
    
    print("Generating strong passwords...")
    strong_passwords = generate_strong_passwords(n=n_generated//2)
    
    all_passwords = weak_passwords + strong_passwords
    
    # Add passwords from RockYou if requested
    if include_rockyou and n_rockyou > 0:
        print(f"Loading {n_rockyou} passwords from RockYou dataset...")
        rockyou_passwords = load_rockyou_passwords(sample=True, sample_size=n_rockyou*2)
        
        # Take a random sample of the RockYou passwords
        rockyou_sample = random.sample(rockyou_passwords, min(n_rockyou, len(rockyou_passwords)))
        all_passwords.extend(rockyou_sample)
        
        print(f"Added {len(rockyou_sample)} passwords from RockYou dataset")
    
    # Calculate strength for each password
    print("Calculating password strengths...")
    strengths = [calculate_password_strength(pwd) for pwd in all_passwords]
    
    # Create additional features
    print("Extracting features...")
    features = []
    for pwd in all_passwords:
        # Basic features
        length = len(pwd)
        uppercase_count = sum(1 for c in pwd if c.isupper())
        lowercase_count = sum(1 for c in pwd if c.islower())
        digit_count = sum(1 for c in pwd if c.isdigit())
        special_count = sum(1 for c in pwd if not c.isalnum())
        unique_char_ratio = len(set(pwd)) / len(pwd) if pwd else 0
        
        # Calculate entropy
        char_freq = {}
        for char in pwd:
            char_freq[char] = char_freq.get(char, 0) + 1
        entropy = -sum((freq/len(pwd)) * np.log2(freq/len(pwd)) for freq in char_freq.values())
        
        # Pattern detection
        has_common_pattern = 0
        common_patterns = [
            r'\b(password|pass|pwd)\b',  # Common password words
            r'\b(123|abc|qwerty)\b',     # Common sequences
            r'\b(admin|root|user)\b',    # Common usernames
            r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b',  # Months
            r'\b(barclays|bank|secure|login)\b',  # Banking related
            r'\b(19\d{2}|20\d{2})\b'    # Years
        ]
        for pattern in common_patterns:
            if re.search(pattern, pwd.lower()):
                has_common_pattern = 1
                break
        
        # Sequence detection
        has_sequential_chars = 0
        for i in range(len(pwd)-2):
            if (ord(pwd[i]) + 1 == ord(pwd[i+1]) and 
                ord(pwd[i+1]) + 1 == ord(pwd[i+2])) or \
               (ord(pwd[i]) - 1 == ord(pwd[i+1]) and 
                ord(pwd[i+1]) - 1 == ord(pwd[i+2])):
                has_sequential_chars = 1
                break
        
        # Repeated characters
        has_repeated_chars = 0
        for i in range(len(pwd)-2):
            if pwd[i] == pwd[i+1] == pwd[i+2]:
                has_repeated_chars = 1
                break
        
        # Hash computation time as a proxy for computational complexity
        start_time = time.time()
        hashlib.sha256(pwd.encode()).hexdigest()
        hash_computation_time = time.time() - start_time
        
        # RockYou dataset feature
        in_rockyou = is_in_rockyou(pwd)
        
        features.append({
            'password': pwd,
            'length': length,
            'uppercase_count': uppercase_count,
            'lowercase_count': lowercase_count,
            'digit_count': digit_count,
            'special_count': special_count,
            'unique_char_ratio': unique_char_ratio,
            'entropy': entropy,
            'has_common_pattern': has_common_pattern,
            'has_sequential_chars': has_sequential_chars,
            'has_repeated_chars': has_repeated_chars,
            'hash_computation_time': hash_computation_time,
            'in_rockyou': in_rockyou,  # New feature indicating if password is in RockYou
            'strength': strengths[all_passwords.index(pwd)]
        })
    
    # Create DataFrame
    df = pd.DataFrame(features)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    print(f"Dataset saved to {output_file}")
    
    # Print distribution of strength levels
    strength_counts = df['strength'].value_counts().sort_index()
    print("\nStrength distribution:")
    for strength, count in strength_counts.items():
        print(f"Strength {strength}: {count} passwords ({count/len(df)*100:.1f}%)")
    
    # Print RockYou statistics
    rockyou_count = df['in_rockyou'].sum()
    print(f"\nPasswords in RockYou dataset: {rockyou_count} ({rockyou_count/len(df)*100:.1f}%)")
    
    return df


if __name__ == "__main__":
    # Create output directory if it doesn't exist
    os.makedirs("data", exist_ok=True)
    
    # Generate dataset with RockYou passwords
    df = generate_dataset("data/password_dataset.csv", n_samples=5000, include_rockyou=True, rockyou_ratio=0.3)
    
    # Split into train and test sets
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['strength'])
    
    # Save train and test sets
    train_df.to_csv("data/train_dataset.csv", index=False)
    test_df.to_csv("data/test_dataset.csv", index=False)
    
    print(f"\nTraining set: {len(train_df)} passwords")
    print(f"Test set: {len(test_df)} passwords")