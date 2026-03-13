import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

print(f"URL loaded: {url}")        # add this temporarily
print(f"KEY loaded: {key[:20] if key else 'MISSING'}")  # add this temporarily

supabase: Client = create_client(url, key)