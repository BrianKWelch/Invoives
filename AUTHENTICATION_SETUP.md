# Authentication Setup for Streamlit Cloud

## Critical Security Issue Fixed
The app now requires authentication to prevent unauthorized access. Each user has their own isolated database.

## Setup Instructions

### 1. Generate Password Hash

First, generate a password hash using the helper script:

```bash
python generate_password_hash.py your_secure_password
```

This will output a hash that you'll use in Streamlit secrets.

### 2. Configure Streamlit Cloud Secrets

1. Go to your Streamlit Cloud app: https://share.streamlit.io/
2. Navigate to your app's settings
3. Click on **"Secrets"** in the left sidebar
4. Add the following configuration:

```toml
[users]
admin = "YOUR_PASSWORD_HASH_HERE"
```

Replace `admin` with your desired username and `YOUR_PASSWORD_HASH_HERE` with the hash generated in step 1.

### 3. Example

If your password is "MySecurePass123", run:
```bash
python generate_password_hash.py MySecurePass123
```

Then add to secrets:
```toml
[users]
admin = "a1b2c3d4e5f6..."  # (the full hash output)
```

### 4. Multiple Users

You can add multiple users:
```toml
[users]
admin = "hash1"
user1 = "hash2"
user2 = "hash3"
```

### 5. Database Isolation

Each user gets their own isolated database:
- Admin user: `data_admin.db`
- User1: `data_user1.db`
- etc.

This ensures complete data separation between users.

## Important Notes

- **Never commit** `.streamlit/secrets.toml` to your repository
- Passwords are hashed using SHA256
- Sessions persist until logout or browser close
- If secrets are not configured, the app will show a login screen but authentication will fail

## Troubleshooting

If you can't login:
1. Verify the secrets are configured correctly in Streamlit Cloud
2. Make sure you're using the exact username and password
3. Regenerate the password hash if needed
4. Check Streamlit Cloud logs for errors

