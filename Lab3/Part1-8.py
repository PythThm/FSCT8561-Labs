import hashlib, time, pyotp

# Part 2
def hash_password(password):

    return hashlib.sha256(
        password.encode()
    ).hexdigest()

def verify_password(password, stored_hash):

    entered_hash = hash_password(
        password
    )

    if entered_hash == stored_hash:
        print("Password accepted")
        return True
    else:
        print("Password rejected")
        return False

stored_hash = hash_password("Cyber123!")
# verify_password = verify_password("Cyber123!", stored_hash)

# Generate TOTP Secret and user db
secret = pyotp.random_base32()

user = {
    "alice": {
        "password_hash": stored_hash,
        "totp_secret": secret
    }
}

# print(
#     "Alice's TOTP secret:",
#     user["alice"]["totp_secret"]
# )

# settng TOTP, TOTP verification
def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

# Create OTP with Alice's secret
totp = pyotp.TOTP(user["alice"]["totp_secret"])
current_otp = totp.now()
print("current otp: ", current_otp)

# 1. Verify the current OTP
user_otp = input("Enter the current OTP: ")

if verify_otp(secret, user_otp):
    print("OTP accepted")
else:
    print("Invalid OTP")


# 2. Test an incorrect six-digit value
incorrect_otp = input("Enter an incorrect six-digit OTP: ")

if verify_otp(secret, incorrect_otp):
    print("OTP accepted")
else:
    print("Invalid OTP")


# 3. Test a previously generated OTP after it expires
old_otp = totp.now()

print("Wait for the OTP to expire...")
time.sleep(31)

if verify_otp(secret, old_otp):
    print("Old OTP accepted")
else:
    print("Old OTP expired or invalid")

