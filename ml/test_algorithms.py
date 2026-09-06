import time
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier


def benchmark(name, func):
    print(f"\n{name}")
    start = time.time()
    func()
    print(f"Time: {time.time()-start:.3f}s")


def test_random_forest():
    X = np.random.rand(1000,10)
    y = np.random.randint(0,2,1000)

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X,y)
    print("Prediction:", model.predict(X[:5]))


def test_xgboost():
    X = np.random.rand(1000,10)
    y = np.random.randint(0,2,1000)

    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X,y)
    print("Prediction:", model.predict(X[:5]))


def test_isolation():
    X = np.random.rand(1000,10)

    model = IsolationForest(
        n_estimators=100,
        random_state=42
    )

    model.fit(X)
    print("Prediction:", model.predict(X[:5]))


print("="*50)
print("NetSentry AI CPU Benchmark")
print("="*50)

benchmark("Random Forest", test_random_forest)
benchmark("XGBoost", test_xgboost)
benchmark("Isolation Forest", test_isolation)

print("\nAll core algorithms are working.")