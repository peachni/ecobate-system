from werkzeug.security import generate_password_hash

hashed = generate_password_hash("Admin123!@#")
print("YOUR HASH IS:", hashed)