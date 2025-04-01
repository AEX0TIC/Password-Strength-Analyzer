import os
import requests
import gzip
import shutil
import hashlib
import pandas as pd
import numpy as np
from tqdm import tqdm
import random
import string

# Constants
# Primary and fallback URLs for the RockYou dataset
ROCKYOU_URLS = [
    "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.gz",
    "https://downloads.skullsecurity.org/passwords/rockyou.txt.gz",
    "https://github.com/ohmybahgosh/RockYou2021.txt/raw/main/rockyou.txt.gz",
    "https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz",
    "https://github.com/zacheller/rockyou/raw/master/rockyou.txt.gz"
]
ROCKYOU_DIR = "data/rockyou"
ROCKYOU_GZ_PATH = f"{ROCKYOU_DIR}/rockyou.txt.gz"
ROCKYOU_TXT_PATH = f"{ROCKYOU_DIR}/rockyou.txt"
ROCKYOU_SAMPLE_PATH = f"{ROCKYOU_DIR}/rockyou_sample.txt"

# MD5 hash of the original rockyou.txt.gz file for verification
# Note: This may vary depending on the source
ROCKYOU_MD5 = "5961d7a6e05d3a965c465c06ec7d6110"

def download_rockyou_dataset():
    """Download the RockYou dataset if it doesn't exist."""
    # Create directory if it doesn't exist
    os.makedirs(ROCKYOU_DIR, exist_ok=True)
    
    # Check if the file already exists
    if os.path.exists(ROCKYOU_TXT_PATH):
        print(f"RockYou dataset already exists at {ROCKYOU_TXT_PATH}")
        return ROCKYOU_TXT_PATH
    
    # Check if the compressed file already exists
    if os.path.exists(ROCKYOU_GZ_PATH):
        print(f"Compressed RockYou dataset already exists at {ROCKYOU_GZ_PATH}")
    else:
        # Try each URL in order until one works
        download_success = False
        download_errors = []
        
        for url in ROCKYOU_URLS:
            try:
                print(f"Attempting to download RockYou dataset from {url}...")
                response = requests.get(url, stream=True, timeout=30)
                response.raise_for_status()
                
                # Get total file size
                total_size = int(response.headers.get('content-length', 0))
                block_size = 8192
                
                # Download with progress bar
                with open(ROCKYOU_GZ_PATH, 'wb') as f:
                    with tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading") as pbar:
                        for chunk in response.iter_content(chunk_size=block_size):
                            if chunk:
                                f.write(chunk)
                                pbar.update(len(chunk))
                
                download_success = True
                print(f"Successfully downloaded from {url}")
                break
            except (requests.RequestException, IOError) as e:
                error_msg = f"Failed to download from {url}: {str(e)}"
                print(error_msg)
                download_errors.append(error_msg)
                continue
        
        if not download_success:
            error_details = "\n- " + "\n- ".join(download_errors)
            print(f"All download attempts failed with the following errors:{error_details}")
            print("Falling back to generated password list.")
            return None
        
        # Verify the download if MD5 is provided
        try:
            with open(ROCKYOU_GZ_PATH, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                if file_hash != ROCKYOU_MD5:
                    print(f"Warning: MD5 hash of downloaded file ({file_hash}) does not match expected hash ({ROCKYOU_MD5})")
                    print("This may be due to using an alternative source. Continuing anyway...")
        except Exception as e:
            print(f"Warning: Could not verify MD5 hash: {str(e)}")
    
    # Extract the file
    try:
        print(f"Extracting {ROCKYOU_GZ_PATH}...")
        with gzip.open(ROCKYOU_GZ_PATH, 'rb') as f_in:
            with open(ROCKYOU_TXT_PATH, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        print(f"RockYou dataset extracted to {ROCKYOU_TXT_PATH}")
        return ROCKYOU_TXT_PATH
    except Exception as e:
        print(f"Error extracting file: {str(e)}")
        print("Falling back to generated password list.")
        return None

def generate_fallback_passwords(sample_size=100000, min_length=6):
    """Generate a fallback list of passwords when RockYou dataset is unavailable.
    
    This function creates a synthetic dataset that mimics common password patterns
    found in leaked password databases like RockYou.
    
    Args:
        sample_size: Number of passwords to generate
        min_length: Minimum password length
        
    Returns:
        List of generated passwords
    """
    print(f"Generating {sample_size} synthetic passwords as RockYou fallback...")
    passwords = []
    
    # Common words to use as password bases
    common_words = [
        "password", "welcome", "qwerty", "monkey", "dragon", "baseball", "football", 
        "letmein", "master", "hello", "princess", "abc123", "123abc", "sunshine", 
        "shadow", "ashley", "michael", "superman", "batman", "trustno1", "iloveyou",
        "admin", "login", "starwars", "whatever", "pokemon", "computer", "internet",
        "cheese", "summer", "winter", "spring", "autumn", "purple", "orange", "yellow",
        "banana", "apple", "chocolate", "secret", "freedom", "flower", "mustang"
    ]
    
    # Common years and number patterns
    years = [str(year) for year in range(1970, 2023)]
    number_patterns = ["123", "1234", "12345", "123456", "54321", "4321", "321", "000", "111", "222"]
    
    # Common special character patterns
    special_patterns = ["!", "@", "#", "$", "%", "*", "!!", "!@", "@#", "#$", "!!!", "123!", "!@#"]
    
    # Generate passwords with different patterns
    while len(passwords) < sample_size:
        pattern_type = random.randint(1, 5)
        
        if pattern_type == 1:
            # Word + Year
            word = random.choice(common_words)
            year = random.choice(years)
            pwd = word + year
        
        elif pattern_type == 2:
            # Word + Numbers
            word = random.choice(common_words)
            numbers = random.choice(number_patterns)
            pwd = word + numbers
        
        elif pattern_type == 3:
            # Word + Special
            word = random.choice(common_words)
            special = random.choice(special_patterns)
            pwd = word + special
        
        elif pattern_type == 4:
            # Word + Word
            word1 = random.choice(common_words)
            word2 = random.choice(common_words)
            pwd = word1 + word2
        
        else:
            # Random string
            length = random.randint(min_length, min_length + 8)
            chars = string.ascii_letters + string.digits
            pwd = ''.join(random.choice(chars) for _ in range(length))
        
        # Ensure minimum length
        if len(pwd) >= min_length:
            # Apply some random transformations
            if random.random() < 0.3:
                # Capitalize first letter
                pwd = pwd[0].upper() + pwd[1:]
            
            if random.random() < 0.2:
                # Replace some letters with numbers (leet speak)
                pwd = pwd.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
            
            passwords.append(pwd)
    
    # Create a sample file for future use
    os.makedirs(ROCKYOU_DIR, exist_ok=True)
    with open(ROCKYOU_SAMPLE_PATH, 'w', encoding='utf-8') as f:
        for pwd in passwords:
            f.write(f"{pwd}\n")
    
    print(f"Created fallback password list with {len(passwords)} passwords")
    print(f"Saved to {ROCKYOU_SAMPLE_PATH}")
    
    return passwords

def create_rockyou_sample(sample_size=100000, min_length=6):
    """Create a sample of the RockYou dataset for faster processing."""
    # Download the dataset if it doesn't exist
    result = download_rockyou_dataset()
    if result is None:
        print("Download failed, using fallback password generation instead.")
        return generate_fallback_passwords(sample_size, min_length)
    
    # Check if sample already exists
    if os.path.exists(ROCKYOU_SAMPLE_PATH):
        print(f"RockYou sample already exists at {ROCKYOU_SAMPLE_PATH}")
        return ROCKYOU_SAMPLE_PATH
    
    # Create a sample of the dataset
    print(f"Creating sample of {sample_size} passwords from RockYou dataset...")
    passwords = []
    
    with open(ROCKYOU_TXT_PATH, 'rb') as f:
        for line in tqdm(f, desc="Reading passwords"):
            try:
                # Decode the line and remove whitespace
                pwd = line.decode('utf-8', errors='ignore').strip()
                
                # Skip passwords that are too short
                if len(pwd) >= min_length:
                    passwords.append(pwd)
                
                # Break if we have enough passwords
                if len(passwords) >= sample_size:
                    break
            except Exception as e:
                # Skip lines that can't be decoded
                continue
    
    # Write the sample to a file
    with open(ROCKYOU_SAMPLE_PATH, 'w', encoding='utf-8') as f:
        for pwd in passwords:
            f.write(f"{pwd}\n")
    
    print(f"RockYou sample created at {ROCKYOU_SAMPLE_PATH} with {len(passwords)} passwords")
    return ROCKYOU_SAMPLE_PATH

def load_rockyou_passwords(sample=True, sample_size=100000, min_length=6):
    """Load passwords from the RockYou dataset.
    
    Args:
        sample: Whether to use a sample of the dataset (faster)
        sample_size: Number of passwords to include in the sample
        min_length: Minimum password length to include
        
    Returns:
        List of passwords from the RockYou dataset
    """
    try:
        if sample:
            # Create a sample if it doesn't exist
            sample_path = create_rockyou_sample(sample_size, min_length)
            
            # Load the sample
            with open(sample_path, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f]
            
            return passwords
        else:
            # Download the dataset if it doesn't exist
            download_rockyou_dataset()
            
            # Load the full dataset
            passwords = []
            with open(ROCKYOU_TXT_PATH, 'rb') as f:
                for line in tqdm(f, desc="Loading RockYou passwords"):
                    try:
                        # Decode the line and remove whitespace
                        pwd = line.decode('utf-8', errors='ignore').strip()
                        
                        # Skip passwords that are too short
                        if len(pwd) >= min_length:
                            passwords.append(pwd)
                    except Exception as e:
                        # Skip lines that can't be decoded
                        continue
            
            return passwords
    except Exception as e:
        print(f"Warning: Could not load RockYou passwords: {str(e)}")
        print("Generating fallback password list instead...")
        return generate_fallback_passwords(sample_size, min_length)

def get_common_password_dict(top_n=10000):
    """Create a dictionary of common passwords from RockYou for fast lookup.
    
    Args:
        top_n: Number of most common passwords to include in the dictionary
        
    Returns:
        Dictionary with passwords as keys for O(1) lookup
    """
    try:
        # Load the RockYou passwords
        passwords = load_rockyou_passwords(sample=True)
        
        # Count frequency of each password
        from collections import Counter
        password_counts = Counter(passwords)
        
        # Get the top N most common passwords
        top_passwords = dict(password_counts.most_common(top_n))
        
        # Convert to a dictionary for O(1) lookup
        common_dict = {pwd: True for pwd in top_passwords.keys()}
        
        print(f"Created dictionary of {len(common_dict)} common passwords")
        return common_dict
    except Exception as e:
        print(f"Warning: Could not create common password dictionary: {str(e)}")
        print("Creating fallback dictionary...")
        # Create a minimal dictionary with the fallback passwords
        fallback_passwords = generate_fallback_passwords(min(top_n, 1000))
        common_dict = {pwd: True for pwd in fallback_passwords}
        print(f"Created fallback dictionary with {len(common_dict)} passwords")
        return common_dict

if __name__ == "__main__":
    # Test the functions
    download_rockyou_dataset()
    create_rockyou_sample()
    passwords = load_rockyou_passwords(sample=True)
    print(f"Loaded {len(passwords)} passwords from RockYou dataset")
    common_dict = get_common_password_dict()
    print(f"Top 5 passwords: {list(common_dict.keys())[:5]}")