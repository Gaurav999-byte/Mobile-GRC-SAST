import joblib

model = joblib.load("rf_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

def predict_severity(text):
    X = vectorizer.transform([text])
    return model.predict(X)[0]