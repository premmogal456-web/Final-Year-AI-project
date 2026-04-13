import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

# Larger dataset
data = {
    "log": [
        # Normal
        "GET /index.html HTTP/1.1",
        "GET /home HTTP/1.1",
        "GET /products HTTP/1.1",
        "GET /about HTTP/1.1",
        "GET /contact HTTP/1.1",
        "GET /profile HTTP/1.1",

        # SQL Injection
        "GET /login.php?id=1' OR '1'='1 HTTP/1.1",
        "GET /page.php?id=5 UNION SELECT * FROM users",
        "GET /item.php?id=10' --",
        "GET /admin.php?id=1' OR 1=1 --",

        # Brute Force
        "POST /admin HTTP/1.1 401",
        "POST /login HTTP/1.1 401",
        "POST /admin HTTP/1.1 401",
        "POST /login HTTP/1.1 401",

        # XSS
        "GET /search?q=<script>alert(1)</script>",
        "GET /page?q=<script>hack()</script>",
        "GET /comment?q=<script>alert('x')</script>"
    ],
    "label": [
        "Normal","Normal","Normal","Normal","Normal","Normal",
        "SQL Injection","SQL Injection","SQL Injection","SQL Injection",
        "Brute Force","Brute Force","Brute Force","Brute Force",
        "XSS","XSS","XSS"
    ]
}

df = pd.DataFrame(data)

vectorizer = TfidfVectorizer(ngram_range=(1,2))
X = vectorizer.fit_transform(df["log"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = LogisticRegression(max_iter=2000)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("✅ Improved Model Trained Successfully!")
