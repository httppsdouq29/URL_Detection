"""
Script dự đoán URL là lành tính hay độc hại sử dụng Random Forest model
"""

import os
import json
import joblib
import pandas as pd
import sys
from extract_url_features import extract_features

# Đường dẫn đến model Random Forest
MODEL_PATH = 'Model_PKL/random_forest_model.pkl'
METADATA_PATH = 'model_metadata_random_forest.json'

CLASS_NAMES = {
    0: 'Lành tính',
    1: 'Độc hại'
}


def load_model_and_metadata():
    """Load model và metadata từ file"""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Không tìm thấy file model: {MODEL_PATH}")
    
    if not os.path.exists(METADATA_PATH):
        raise FileNotFoundError(f"Không tìm thấy file metadata: {METADATA_PATH}")
    
    # Load model
    model = joblib.load(MODEL_PATH)
    
    # Load metadata
    with open(METADATA_PATH, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    
    return model, metadata


def predict_url(url):
    """
    Dự đoán URL là lành tính hay độc hại sử dụng Random Forest
    
    Args:
        url: URL cần kiểm tra
    
    Returns:
        Dictionary chứa kết quả dự đoán
    """
    # Load model và metadata
    model, metadata = load_model_and_metadata()
    
    # Trích xuất đặc trưng từ URL
    features_dict = extract_features(url)
    
    # Lấy danh sách feature columns từ metadata (đảm bảo thứ tự đúng)
    feature_columns = metadata['feature_columns']
    
    # Tạo DataFrame với đúng thứ tự features
    features_df = pd.DataFrame([features_dict])
    features_array = features_df[feature_columns].values
    
    # Dự đoán
    prediction = model.predict(features_array)[0]
    prediction_proba = model.predict_proba(features_array)[0]
    
    # Kết quả
    result = {
        'url': url,
        'model_name': 'Random Forest',
        'prediction': int(prediction),
        'prediction_label': CLASS_NAMES[prediction],
        'probability': {
            'Lành tính': float(prediction_proba[0]) * 100,
            'Độc hại': float(prediction_proba[1]) * 100
        },
        'confidence': float(max(prediction_proba)) * 100
    }
    
    return result


def print_result(result):
    """In kết quả dự đoán"""
    print("\n" + "="*70)
    print(f"URL: {result['url']}")
    print(f"Model: {result['model_name']}")
    print("-"*70)
    print(f"Kết quả dự đoán: {result['prediction_label']}")
    print(f"Độ tin cậy: {result['confidence']:.2f}%")
    print("\nXác suất:")
    print(f"  - Lành tính: {result['probability']['Lành tính']:.2f}%")
    print(f"  - Độc hại:   {result['probability']['Độc hại']:.2f}%")
    print("="*70 + "\n")


def main():
    """Hàm chính"""
    print("\n" + "="*70)
    print("PHÂN LOẠI URL - PHÁT HIỆN PHISHING")
    print("Model: Random Forest")
    print("="*70)
    
    # Nhập URL
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("\nNhập URL cần kiểm tra: ").strip()
    
    if not url:
        print("URL không được để trống!")
        return
    
    # Dự đoán với Random Forest
    result = predict_url(url)
    print_result(result)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nĐã hủy bởi người dùng.")
    except Exception as e:
        print(f"\nLỗi: {str(e)}")
        import traceback
        traceback.print_exc()

