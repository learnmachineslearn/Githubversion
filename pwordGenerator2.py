import random
import string
import re
from datetime import datetime
import gspread
from oauth2client.service_account import ServiceAccountCredentials

# Function to generate a secure password
def generate_secure_password(length=16):
    # Define allowed character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
    restricted_chars = {' ', '\t', '\n', '\\', ':', ';', '<', '>', '|'}

    # Ensure the password has at least one character from each required set
    while True:
        # Build a password pool
        password_pool = uppercase + lowercase + digits + special_chars

        # Generate a random password with at least one character from each required set
        password = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(digits),
            random.choice(special_chars),
        ]

        # Fill the rest of the password with random choices from the pool
        password += random.choices(password_pool, k=length - 4)
        random.shuffle(password)
        password = ''.join(password)

        # Validate the password
        if validate_password(password, restricted_chars):
            return password

# Function to validate the password
def validate_password(password, restricted_chars):
    # Length check
    if len(password) < 8 or len(password) > 64:
        return False
    # Check for restricted characters
    if any(c in restricted_chars for c in password):
        return False
    # Check character composition
    if not re.search(r'[A-Z]', password):  # At least one uppercase
        return False
    if not re.search(r'[a-z]', password):  # At least one lowercase
        return False
    if not re.search(r'[0-9]', password):  # At least one digit
        return False
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:\'",.<>?/]', password):  # At least one special character
        return False
    # No repeated characters
    if re.search(r'(.)\1{2,}', password):  # Avoid 3+ consecutive repeated characters
        return False
    # No sequential patterns
    if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
        return False
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password):
        return False
    return True

# Function to log password details to Google Sheets
def log_to_google_sheets(domain, password):
    # Authenticate with Google Sheets API
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    credentials = ServiceAccountCredentials.from_json_keyfile_name("credentials.json", scope)
    client = gspread.authorize(credentials)

    # Open the spreadsheet and the first worksheet
    sheet = client.open("PasswordLog").sheet1

    # Prepare log entry
    timestamp = datetime.now().strftime("%m-%d-%Y") # Changed the order of the date
    log_entry = [timestamp, domain, password]       # Changed the order of the columns in Googlesheets

    # Append log entry to the sheet
    sheet.append_row(log_entry)
    print(f"Password logged for domain '{domain}' at {timestamp}.")

# Main function to interact with the user
def main():
    while True:
        domain = input("Enter the domain name (or type 'exit' to quit): ").strip()
        if domain.lower() == "exit":
            print("Goodbye!")
            break

        try:
            length = int(input("Enter the desired password length: "))
            if length <= 7:    # Changed the input length from 0 to 7
                print("Password length must be between 8 and 64 characters.")
                continue
        except ValueError:
            print("Please enter a valid number for password length.")
            continue

        # Generate and display secure password
        password = generate_secure_password(length)
        print(f"Generated Secure Password: {password}")

        # Log password details to Google Sheets
        log_to_google_sheets(domain, password)

if __name__ == "__main__":
    main()
