# ============================================
# PhishGuard PH - Step 2: Download Dataset
# ============================================

from ucimlrepo import fetch_ucirepo
import pandas as pd

print("Downloading dataset from UCI... please wait...")
phishing = fetch_ucirepo(id=327)

X = phishing.data.features
y = phishing.data.targets

df = pd.concat([X, y], axis=1)

df.to_csv("phishing_dataset.csv", index=False)

print("\n===== DATASET INFO =====")
print(f"Total records: {len(df)}")
print(f"Total columns: {len(df.columns)}")
print(f"\nFirst 5 rows:")
print(df.head())
print(f"\nPhishing vs Legitimate count:")
print(y.value_counts())
print("\nSaved as phishing_dataset.csv")
print("DONE!")