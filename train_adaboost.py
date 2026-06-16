import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time

from sklearn.model_selection import train_test_split
from sklearn.ensemble import AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

def print_classification_report_percent(y_true, y_pred, target_names=None):
    """In classification report dưới dạng phần trăm"""
    report_dict = classification_report(
        y_true, y_pred,
        target_names=target_names,
        output_dict=True,
        zero_division=0
    )
    
    # Header
    print(f"{'':<20} {'precision':<12} {'recall':<12} {'f1-score':<12} {'support':<12}")
    print("-" * 68)
    
    # In từng class
    for key in report_dict.keys():
        if key in ['accuracy', 'macro avg', 'weighted avg']:
            continue
        metrics = report_dict[key]
        name = key if target_names is None else key
        print(f"{name:<20} {metrics['precision']*100:>10.4f}  {metrics['recall']*100:>10.4f}  {metrics['f1-score']*100:>10.4f}  {int(metrics['support']):>10}")
    
    print()
    # In accuracy
    total_support = sum([report_dict[k]['support'] for k in report_dict.keys() if k not in ['accuracy', 'macro avg', 'weighted avg']])
    print(f"{'accuracy':<20} {report_dict['accuracy']*100:>10.4f}  {'':>10}  {'':>10}  {int(total_support):>10}")
    
    # In macro avg và weighted avg
    print(f"{'macro avg':<20} {report_dict['macro avg']['precision']*100:>10.4f}  {report_dict['macro avg']['recall']*100:>10.4f}  {report_dict['macro avg']['f1-score']*100:>10.4f}  {int(report_dict['macro avg']['support']):>10}")
    print(f"{'weighted avg':<20} {report_dict['weighted avg']['precision']*100:>10.4f}  {report_dict['weighted avg']['recall']*100:>10.4f}  {report_dict['weighted avg']['f1-score']*100:>10.4f}  {int(report_dict['weighted avg']['support']):>10}")

if __name__ == "__main__":
    t_start = time.time()
    
    # Đọc dữ liệu
    csv_path = os.path.join('..', 'final_csv', 'url_features_extracted.csv')
    df = pd.read_csv(csv_path)
    X = df.drop('label', axis=1)
    X = X.fillna(0)
    y = df['label']
    
    # Chia dữ liệu
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Khởi tạo và train mô hình
    base_estimator = DecisionTreeClassifier(max_depth=3, random_state=42)
    model = AdaBoostClassifier(
        estimator=base_estimator,
        n_estimators=150,
        learning_rate=1.0,
        random_state=42
    )
    model.fit(X_train, y_train)
    


    
    # Đánh giá mô hình
    
    # Dự đoán
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    
    # Tính metrics cho train
    acc_train = accuracy_score(y_train, y_train_pred)
    f1_train = f1_score(y_train, y_train_pred, zero_division=0)
    recall_train = recall_score(y_train, y_train_pred, zero_division=0)
    precision_train = precision_score(y_train, y_train_pred, zero_division=0)
    
    # Tính metrics cho test
    acc_test = accuracy_score(y_test, y_test_pred)
    f1_test = f1_score(y_test, y_test_pred, zero_division=0)
    recall_test = recall_score(y_test, y_test_pred, zero_division=0)
    precision_test = precision_score(y_test, y_test_pred, zero_division=0)
    
    # In kết quả
    print(f"\nAdaBoost Classifier : Accuracy on training Data: {acc_train:.3f}")
    print(f"AdaBoost Classifier : Accuracy on test Data: {acc_test:.3f}")
    print()
    print(f"AdaBoost Classifier : f1_score on training Data: {f1_train:.3f}")
    print(f"AdaBoost Classifier : f1_score on test Data: {f1_test:.3f}")
    print()
    print(f"AdaBoost Classifier : Recall on training Data: {recall_train:.3f}")
    print(f"AdaBoost Classifier : Recall on test Data: {recall_test:.3f}")
    print()
    print(f"AdaBoost Classifier : precision on training Data: {precision_train:.3f}")
    print(f"AdaBoost Classifier : precision on test Data: {precision_test:.3f}")
    print()
    
    # Classification report
    print("\nClassification Report for AdaBoost Classifier:")
    print_classification_report_percent(
        y_test, y_test_pred,
        target_names=['Lành tính (0)', 'Độc hại (1)']
    )
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_test_pred)
    
    # Vẽ biểu đồ
    os.makedirs(os.path.join('..', 'picture', 'confusion'), exist_ok=True)
    labels = ['Lành tính', 'Độc hại']
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
    ax.set_title('Confusion Matrix - AdaBoost')
    ax.set_xlabel('Dự đoán')
    ax.set_ylabel('Thực tế')
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(labels)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'), ha='center', va='center', color='black')
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    plt.tight_layout()
    plt.savefig(os.path.join('..', 'picture', 'confusion', 'confusion_matrix_adaboost.png'), bbox_inches='tight')
    plt.close(fig)
    
    # Vẽ feature importance
    os.makedirs(os.path.join('..', 'picture', 'Feature'), exist_ok=True)
    importances = model.feature_importances_
    df_imp = pd.DataFrame({'Feature': X.columns, 'Importance': importances}).sort_values('Importance', ascending=False)
    data = df_imp.head(10).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(data['Feature'], data['Importance'], color='#1f77b4')
    ax.set_title('Top 10 đặc trưng quan trọng nhất - AdaBoost')
    ax.set_xlabel('Mức độ quan trọng')
    ax.set_ylabel('Đặc trưng')
    plt.tight_layout()
    plt.savefig(os.path.join('..', 'picture', 'Feature', 'feature_importance_adaboost.png'), bbox_inches='tight')
    plt.close(fig)
    
    # Lưu mô hình
    os.makedirs(os.path.join('..', 'Model_PKL'), exist_ok=True)
    joblib.dump(model, os.path.join('..', 'Model_PKL', 'adaboost_model.pkl'))
    
    # Lưu metadata
    metrics = {
        'train': {
            'accuracy': acc_train,
            'f1_score': f1_train,
            'recall': recall_train,
            'precision': precision_train
        },
        'test': {
            'accuracy': acc_test,
            'f1_score': f1_test,
            'recall': recall_test,
            'precision': precision_test
        },
        'confusion_matrix': cm.tolist()
    }
    
    with open(os.path.join('..', 'model_metadata_adaboost.json'), 'w', encoding='utf-8') as f:
        json.dump({
            'model_name': 'AdaBoost',
            'params': {
                'n_estimators': 150,
                'learning_rate': 1.0,
                'estimator__max_depth': 3
            },
            'feature_columns': list(X.columns),
            'metrics': metrics
        }, f, ensure_ascii=False, indent=2)
    
    t_end = time.time()
    print(f"\nTổng thời gian chạy: {t_end - t_start:.2f}s")
    print(f"Test Accuracy: {acc_test:.4f}")
    print(f"Test F1 Score: {f1_test:.4f}")
    print(f"Test Precision: {precision_test:.4f}")
    print(f"Test Recall: {recall_test:.4f}")

