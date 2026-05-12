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
# HYBRID ML RISK PREDICTION
# =========================
def predict_risk(text):

    try:

        issue = text.lower()

        # =========================
        # ML MODEL EXECUTION
        # =========================
        X = vectorizer.transform([text])

        ml_prediction = model.predict(X)[0]

        # =========================
        # HYBRID INTELLIGENCE RULES
        # =========================

        # Critical Risks
        if "api" in issue or "key" in issue:

            return {
                "prediction": "Critical",
                "confidence": 96
            }

        # High Risks
        elif "debuggable" in issue:

            return {
                "prediction": "High",
                "confidence": 88
            }

        # Medium Risks
        elif "http" in issue:

            return {
                "prediction": "Medium",
                "confidence": 74
            }

        elif "random" in issue:

            return {
                "prediction": "Medium",
                "confidence": 69
            }

        # Low Risks
        elif "backup" in issue:

            return {
                "prediction": "Low",
                "confidence": 58
            }

        # =========================
        # FALLBACK ML PREDICTION
        # =========================
        else:

            probabilities = model.predict_proba(X)[0]

            confidence = round(max(probabilities) * 100, 2)

            return {
                "prediction": str(ml_prediction),
                "confidence": confidence
            }

    except Exception as e:

        return {
            "prediction": "Unknown",
            "confidence": 0
        }