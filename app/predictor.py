import joblib

# =========================
# LOAD ML MODEL + VECTORIZER
# =========================
model = joblib.load("rf_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# =========================
# BASIC SEVERITY PREDICTION
# =========================
def predict_severity(text):

    X = vectorizer.transform([text])

    prediction = model.predict(X)[0]

    return prediction


# =========================
# ML RISK PREDICTION
# =========================
def predict_risk(text):

    try:

        # convert text into vector
        X = vectorizer.transform([text])

        # prediction label
        prediction = model.predict(X)[0]

        # probability scores
        probabilities = model.predict_proba(X)[0]

        # highest confidence score
        confidence = round(max(probabilities) * 100, 2)

        return {
            "prediction": str(prediction),
            "confidence": confidence
        }

    except Exception as e:

        return {
            "prediction": "Unknown",
            "confidence": 0
        }