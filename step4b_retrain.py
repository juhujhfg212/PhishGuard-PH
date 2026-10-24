# ============================================
# PhishGuard PH - Step 4b: Retrain (URL-Only)
# ============================================

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

# --- 1. Load data ---
print("Loading data...")
train = pd.read_csv("train_data.csv")
test = pd.read_csv("test_data.csv")

# --- 2. Select ONLY URL-extractable features ---
url_features = [
    'having_ip_address',
    'url_length',
    'shortining_service',
    'having_at_symbol',
    'double_slash_redirecting',
    'prefix_suffix',
    'having_sub_domain',
    'sslfinal_state',
    'port',
    'https_token',
    'submitting_to_email',
    'abnormal_url',
    'redirect',
    'on_mouseover'
]

# Check which features actually exist in our dataset
available_features = [f for f in url_features if f in train.columns]
missing_features = [f for f in url_features if f not in train.columns]

print(f"\nUsing {len(available_features)} URL-based features:")
for f in available_features:
    print(f"  - {f}")

if missing_features:
    print(f"\nSkipped (not in dataset): {missing_features}")

X_train = train[available_features]
y_train = train['result']
X_test = test[available_features]
y_test = test['result']

# --- 3. Train Logistic Regression ---
print("\n" + "="*50)
print("MODEL 1: Logistic Regression (URL-only)")
print("="*50)

lr = LogisticRegression(max_iter=1000, random_state=42)
lr.fit(X_train, y_train)
lr_pred = lr.predict(X_test)

print(f"  Accuracy:  {accuracy_score(y_test, lr_pred):.4f}")
print(f"  Precision: {precision_score(y_test, lr_pred):.4f}")
print(f"  Recall:    {recall_score(y_test, lr_pred):.4f}")
print(f"  F1-Score:  {f1_score(y_test, lr_pred):.4f}")

# --- 4. Train Random Forest ---
print("\n" + "="*50)
print("MODEL 2: Random Forest (URL-only)")
print("="*50)

rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)

print(f"  Accuracy:  {accuracy_score(y_test, rf_pred):.4f}")
print(f"  Precision: {precision_score(y_test, rf_pred):.4f}")
print(f"  Recall:    {recall_score(y_test, rf_pred):.4f}")
print(f"  F1-Score:  {f1_score(y_test, rf_pred):.4f}")

# --- 5. Save winner + feature list ---
print("\n" + "="*50)
print("COMPARISON")
print("="*50)

lr_acc = accuracy_score(y_test, lr_pred)
rf_acc = accuracy_score(y_test, rf_pred)

print(f"Logistic Regression: {lr_acc:.4f}")
print(f"Random Forest:       {rf_acc:.4f}")

if rf_acc >= lr_acc:
    print("\nWINNER: Random Forest!")
    joblib.dump(rf, "phishguard_model.pkl")
else:
    print("\nWINNER: Logistic Regression!")
    joblib.dump(lr, "phishguard_model.pkl")

# Save the feature list so the app uses the exact same features
joblib.dump(available_features, "feature_list.pkl")

print("Saved phishguard_model.pkl and feature_list.pkl")
print("DONE!")