import os
import sys
import shutil

# Add the project directory to the path
sys.path.append('d:/Barclays ML Project')

# Import the rockyou_utils module
import rockyou_utils

def test_download():
    print("\n=== Testing RockYou Download Functionality ===")
    
    # Define paths
    rockyou_dir = rockyou_utils.ROCKYOU_DIR
    rockyou_txt = rockyou_utils.ROCKYOU_TXT_PATH
    rockyou_gz = rockyou_utils.ROCKYOU_GZ_PATH
    
    # Check if files already exist
    txt_exists = os.path.exists(rockyou_txt)
    gz_exists = os.path.exists(rockyou_gz)
    
    print(f"Current status:")
    print(f"- RockYou directory exists: {os.path.exists(rockyou_dir)}")
    print(f"- RockYou text file exists: {txt_exists}")
    print(f"- RockYou gz file exists: {gz_exists}")
    
    # If files exist, rename them temporarily to force a download
    if txt_exists:
        backup_txt = f"{rockyou_txt}.backup"
        print(f"\nTemporarily renaming {rockyou_txt} to {backup_txt}")
        os.rename(rockyou_txt, backup_txt)
    
    if gz_exists:
        backup_gz = f"{rockyou_gz}.backup"
        print(f"Temporarily renaming {rockyou_gz} to {backup_gz}")
        os.rename(rockyou_gz, backup_gz)
    
    # Test the download function
    print("\nTesting download_rockyou_dataset() function...")
    try:
        result = rockyou_utils.download_rockyou_dataset()
        if result:
            print(f"\nSUCCESS: Download completed successfully!")
            print(f"Downloaded file: {result}")
        else:
            print(f"\nNOTE: Download function returned None, fallback mechanism activated")
    except Exception as e:
        print(f"\nERROR: Download failed with exception: {str(e)}")
    
    # Restore original files
    print("\nCleaning up test environment...")
    
    # Remove any newly downloaded files
    if not txt_exists and os.path.exists(rockyou_txt):
        os.remove(rockyou_txt)
        print(f"Removed newly downloaded {rockyou_txt}")
    
    if not gz_exists and os.path.exists(rockyou_gz):
        os.remove(rockyou_gz)
        print(f"Removed newly downloaded {rockyou_gz}")
    
    # Restore backup files
    if txt_exists:
        if os.path.exists(backup_txt):
            if os.path.exists(rockyou_txt):
                os.remove(rockyou_txt)
            os.rename(backup_txt, rockyou_txt)
            print(f"Restored original {rockyou_txt}")
    
    if gz_exists:
        if os.path.exists(backup_gz):
            if os.path.exists(rockyou_gz):
                os.remove(rockyou_gz)
            os.rename(backup_gz, rockyou_gz)
            print(f"Restored original {rockyou_gz}")

if __name__ == "__main__":
    test_download()