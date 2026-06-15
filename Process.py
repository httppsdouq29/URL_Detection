import pandas as pd
from pathlib import Path

def combine_salt_datasets():
    salt_dataset_dir = Path("Salt_dataset")
    csv_files = ["1_data.csv", "2_data.csv", "3_data.csv", "4_data.csv", "5_data.csv", "6_data.csv"]
    dataframes = []

    for file_name in csv_files:
        file_path = salt_dataset_dir / file_name
        if not file_path.exists():
            continue
        
        try:
            df = pd.read_csv(file_path)
            df.columns = df.columns.str.lower()
            
            url_col = None
            label_col = None
            for col in df.columns:
                if 'url' in col.lower() and url_col is None:
                    url_col = col
                if 'label' in col.lower() and label_col is None:
                    label_col = col
            
            if url_col is None or label_col is None:
                continue
            
            df_clean = pd.DataFrame({'url': df[url_col], 'label': df[label_col]})
            df_clean = df_clean.dropna()
            df_clean['label'] = df_clean['label'].astype(int)
            dataframes.append(df_clean)
            
        except Exception:
            continue
    
    if not dataframes:
        return None
    
    combined_df = pd.concat(dataframes, ignore_index=True)
    combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
    legitimate_df = combined_df[combined_df['label'] == 0].head(400000)
    phishing_df = combined_df[combined_df['label'] == 1]
    combined_df = pd.concat([legitimate_df, phishing_df], ignore_index=True)
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    count_labels(combined_df)
    
    output_dir = Path("final_csv")
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "final_dataset.csv"
    combined_df[['url', 'label']].to_csv(output_path, index=False)
    
    return combined_df

def count_labels(df):
    legitimate = len(df[df['label'] == 0])
    phishing = len(df[df['label'] == 1])
    total = len(df)
    
    print(f"URL lành tính (label 0): {legitimate} ({legitimate/total*100:.2f}%)")
    print(f"URL độc hại (label 1): {phishing} ({phishing/total*100:.2f}%)")
    print(f"Tổng số URL: {total}")

if __name__ == "__main__":
    combine_salt_datasets()
