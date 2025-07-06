# train_classifier.py
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import argparse

def train_model(input_csv, output_model):
    # Load dataset
    global proto_encoder
    df = pd.read_csv(input_csv)

    # Drop non-numeric columns (IP addresses)
    X = df.drop(["Label", "src_ip", "dst_ip"], axis=1)
    # Encode protocol column (TCP,UDP) to integers
    if 'protocol' in X.columns and X['protocol'].dtype == 'object':
        proto_encoder = LabelEncoder()
        X['protocol'] = proto_encoder.fit_transform(X['protocol'])
    y = df["Label"]

    # Encode labels to integers (e.g., voip = 0, video = 1, bulk = 2)
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42
    )

    # Train Decision Tree
    clf = DecisionTreeClassifier(criterion="entropy", max_depth=10)
    clf.fit(X_train, y_train)

    # Evaluation
    print("[*] Classification Report:")
    print(classification_report(y_test, clf.predict(X_test), target_names=le.classes_))
    print("[*] Confusion Matrix:")
    print(confusion_matrix(y_test, clf.predict(X_test)))

    # Cross-validation
    scores = cross_val_score(clf, X, y_encoded, cv=5)
    print(f"[*] Cross-validation accuracy: {scores.mean():.4f}")

    # Save model, encoders, feature order
    joblib.dump(clf, output_model)
    joblib.dump(le, output_model.replace(".pkl", "_labels.pkl"))
    joblib.dump(proto_encoder, output_model.replace(".pkl", "_proto.pkl"))
    joblib.dump(X.columns.tolist(), output_model.replace(".pkl", "_features.pkl"))

    print(f"[+] Model saved to {output_model}")
    print(f"[+] Label encoder saved to {output_model.replace('.pkl', '_labels.pkl')}")
    print(f"[+] Protocol encoder saved to {output_model.replace('.pkl', '_proto.pkl')}")
    print(f"[+] Feature order saved to {output_model.replace('.pkl', '_features.pkl')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv", help="Preprocessed flow dataset CSV")
    parser.add_argument("output_model", help="Filename to save the trained model (e.g., model.pkl)")
    args = parser.parse_args()

    train_model(args.input_csv, args.output_model)