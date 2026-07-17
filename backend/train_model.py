import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle  # joblib ki jagah pickle use kar rahe hain compatibility ke liye
import os

# Dataset path
file_path = 'data/KDDTrain+.txt'

print("--- AI Training Process Started ---")

try:
    # Check if the dataset file exists
    if not os.path.exists(file_path):
        print(f"Error: '{file_path}' not found! Please ensure the file is in the 'data' folder.")
    else:
        # 1. Load the Dataset
        df = pd.read_csv(file_path, header=None)
        
        # 2. Select Relevant Columns
        relevant_cols = [0, 1, 2, 3, 4, 5, 6, 7, 8, -2] 
        df = df.iloc[:, relevant_cols]
        df.columns = [
            "duration", "protocol_type", "service", "flag", 
            "src_bytes", "dst_bytes", "land", "wrong_fragment", 
            "urgent", "class"
        ]

        # 3. Encoding: Convert Text Categories to Numbers
        # Hum label encoders ko bhi save karenge taaki prediction ke waqt error na aaye
        for col in ["protocol_type", "service", "flag", "class"]:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))

        # 4. Define Features (X) and Target (y)
        X = df.drop('class', axis=1)
        y = df['class']

        # 5. Model Training
        print("AI is learning network patterns... (Please wait 10-15 seconds)")
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)

        # 6. Save the Trained Model using PICKLE
        # 'wb' ka matlab hai Write Binary
        with open('anomaly_model.pkl', 'wb') as f:
            pickle.dump(model, f)
        
        print("\n" + "="*40)
        print("SUCCESS! 'anomaly_model.pkl' has been created in the root folder.")
        print("="*40)

except Exception as e:
    print(f"An unexpected error occurred: {e}")