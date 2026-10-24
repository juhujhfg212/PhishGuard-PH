# ============================================
# PhishGuard PH - Step 4: Train & Compare Models
# ============================================

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import joblib

# --- 1. Load prepared data ---
print("Loading training and testing data...")
train = pd.read_csv("train_data.csv")
test = pd.read_csv("test_data.csv")

X_train = train.drop('result', axis=1)
y_train = train['result']
X_test = test.drop('result', axis=1)
y_test = test['result']

# =============================================
# MODEL 1: Logistic Regression (Baseline)
# =============================================
print("\n" + "="*50)
print("TRAINING MODEL 1: Logistic Regression")
print("="*50)

lr_model = LogisticRegression(max_iter=1000, random_state=42)
lr_model.fit(X_train, y_train)
lr_pred = lr_model.predict(X_test)

print("\nLogistic Regression Results:")
print(f"  Accuracy:  {accuracy_score(y_test, lr_pred):.4f}")
print(f"  Precision: {precision_score(y_test, lr_pred):.4f}")
print(f"  Recall:    {recall_score(y_test, lr_pred):.4f}")
print(f"  F1-Score:  {f1_score(y_test, lr_pred):.4f}")
print(f"\nConfusion Matrix:")
print(confusion_matrix(y_test, lr_pred))

# =============================================
# MODEL 2: Random Forest (Challenger)
# =============================================
print("\n" + "="*50)
print("TRAINING MODEL 2: Random Forest")
print("="*50)

rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)

print("\nRandom Forest Results:")
print(f"  Accuracy:  {accuracy_score(y_test, rf_pred):.4f}")
print(f"  Precision: {precision_score(y_test, rf_pred):.4f}")
print(f"  Recall:    {recall_score(y_test, rf_pred):.4f}")
print(f"  F1-Score:  {f1_score(y_test, rf_pred):.4f}")
print(f"\nConfusion Matrix:")
print(confusion_matrix(y_test, rf_pred))

# =============================================
# COMPARE & SAVE THE WINNER
# =============================================
print("\n" + "="*50)
print("COMPARISON")
print("="*50)

lr_acc = accuracy_score(y_test, lr_pred)
rf_acc = accuracy_score(y_test, rf_pred)

print(f"Logistic Regression Accuracy: {lr_acc:.4f}")
print(f"Random Forest Accuracy:       {rf_acc:.4f}")

if rf_acc >= lr_acc:
    print("\nWINNER: Random Forest!")
    joblib.dump(rf_model, "phishguard_model.pkl")
    print("Saved as phishguard_model.pkl")
else:
    print("\nWINNER: Logistic Regression!")
    joblib.dump(lr_model, "phishguard_model.pkl")
    print("Saved as phishguard_model.pkl")

print("\nDONE! Your AI is trained and saved!")