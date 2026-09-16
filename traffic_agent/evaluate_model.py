import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

MODEL_PATH = "model.pkl"
DATASET_PATH = "logs/traffic_dataset.csv"
PREDICTIONS_OUTPUT = "logs/evaluation_predictions.csv"
METRICS_OUTPUT = "logs/evaluation_metrics.json"


def as_bool_number(series):
    """Convierte True/False del CSV a 1/0."""
    return series.replace(
        {
            "True": 1,
            "False": 0,
            "true": 1,
            "false": 0,
            True: 1,
            False: 0,
        }
    )


def main():
    # 1. Cargar el modelo entrenado
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    feature_columns = artifact["feature_columns"]

    # 2. Cargar las 500 peticiones etiquetadas
    data = pd.read_csv(DATASET_PATH)

    if "label" not in data.columns:
        raise ValueError("traffic_dataset.csv debe incluir la columna 'label'.")

    # 3. Usar exactamente las mismas features del entrenamiento
    X = data[feature_columns].copy()

    if "has_suspicious_chars" in X.columns:
        X["has_suspicious_chars"] = as_bool_number(
            X["has_suspicious_chars"]
        )

    X = X.apply(pd.to_numeric, errors="coerce")

    # Eliminar filas incompletas, si hubiera alguna
    valid_rows = X.notna().all(axis=1)
    X = X.loc[valid_rows]
    evaluated = data.loc[valid_rows].copy()

    # Ground truth: normal=0, attack=1
    y_true = (
        evaluated["label"]
        .astype(str)
        .str.lower()
        .eq("attack")
        .astype(int)
    )

    # Isolation Forest: 1 = normal; -1 = anomalía
    raw_prediction = model.predict(X)

    # Convertimos a nuestro formato: normal=0, attack/anomaly=1
    y_pred = (raw_prediction == -1).astype(int)

    # Un score más alto significa que parece más anómalo
    anomaly_score = -model.decision_function(X)

    # 4. Métricas
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="binary",
        zero_division=0,
    )

    metrics = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "rows_evaluated": int(len(evaluated)),
        "confusion_matrix": {
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp),
        },
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "attack_precision": round(float(precision), 6),
        "attack_recall_detection_rate": round(float(recall), 6),
        "attack_f1": round(float(f1), 6),
        "normal_false_positive_rate": round(
            float(fp / (fp + tn)) if (fp + tn) else 0.0,
            6,
        ),
        "roc_auc_anomaly_score": round(
            float(roc_auc_score(y_true, anomaly_score)),
            6,
        ),
    }

    # 5. Guardar predicción de cada petición
    evaluated["ground_truth"] = y_true.map(
        {0: "normal", 1: "attack"}
    )
    evaluated["prediction"] = pd.Series(
        y_pred, index=evaluated.index
    ).map({0: "normal", 1: "attack"})
    evaluated["anomaly_score"] = anomaly_score
    evaluated["raw_iforest_prediction"] = raw_prediction

    Path("logs").mkdir(exist_ok=True)

    evaluated.to_csv(PREDICTIONS_OUTPUT, index=False)

    with open(METRICS_OUTPUT, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2, ensure_ascii=False)

    # 6. Mostrar resultados
    print("\n=== EVALUACIÓN DEL MODELO ===")
    print(f"Filas evaluadas: {metrics['rows_evaluated']}")
    print(f"Matriz de confusión: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"Accuracy: {metrics['accuracy']:.2%}")
    print(f"Detección de ataques (Recall): {metrics['attack_recall_detection_rate']:.2%}")
    print(f"Precisión de ataques: {metrics['attack_precision']:.2%}")
    print(f"F1 de ataques: {metrics['attack_f1']:.2%}")
    print(f"Falsos positivos normales: {metrics['normal_false_positive_rate']:.2%}")
    print(f"ROC-AUC: {metrics['roc_auc_anomaly_score']:.4f}")
    print(f"\nPredicciones: {PREDICTIONS_OUTPUT}")
    print(f"Métricas: {METRICS_OUTPUT}")


if __name__ == "__main__":
    main()
