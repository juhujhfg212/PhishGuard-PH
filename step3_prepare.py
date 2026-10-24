# ============================================
# PhishGuard PH - Step 3: Clean & Prepare Data
# ============================================

import pandas as pd
from sklearn.model_selection import train_test_split

print("Loading dataset...")
df = pd.read_csv("phishing_dataset.csv")

# --- 1. Check for missing values ---
print("\n===== MISSING VALUES CHECK =====")
missing = df.isnull().sum()
print(f"Total missing values: {missing.sum()}")
if missing.sum() == 0:
    print("No missing values! Data is clean!")
else:
    print("Missing values found:")
    print(missing[missing > 0])

# --- 2. Convert labels: -1 -> 0 (phishing), 1 stays 1 (legit) ---
print("\n===== LABEL CONVERSION =====")
print("Before:", df['result'].unique())
df['result'] = df['result'].map({-1: 0, 1: 1})
print("After: ", df['result'].unique())
print("  0 = Phishing, 1 = Legitimate")

# --- 3. Separate features (X) and target (y) ---
X = df.drop('result', axis=1)
y = df['result']

# --- 4. Split into training (80%) and testing (20%) ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\n===== DATA SPLIT =====")
print(f"Training set: {len(X_train)} records")
print(f"Testing set:  {len(X_test)} records")
print(f"Total:        {len(X_train) + len(X_test)} records")

# --- 5. Save the prepared data ---
train_data = pd.concat([X_train, y_train], axis=1)
test_data = pd.concat([X_test, y_test], axis=1)
train_data.to_csv("train_data.csv", index=False)
test_data.to_csv("test_data.csv", index=False)

print("\nSaved train_data.csv and test_data.csv")
print("DONE! Data is ready for ML!")