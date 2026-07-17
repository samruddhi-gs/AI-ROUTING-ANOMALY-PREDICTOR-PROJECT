import pandas as pd

# KDD dataset ke column names (41 features + 1 label)
columns = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
           "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
           "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
           "num_shells","num_access_files","num_outbound_cmds","is_host_login",
           "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
           "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
           "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
           "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
           "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
           "dst_host_rerror_rate","dst_host_srv_rerror_rate","label", "difficulty_level"]

# Aapke 'data' folder se file uthana
try:
    df = pd.read_csv('data/KDDTest+.txt', header=None, names=columns)
    # Humein sirf kaam ke columns dashboard ke liye chahiye
    df_to_save = df[['duration', 'protocol_type', 'service', 'src_bytes', 'dst_bytes', 'label']]
    df_to_save.to_csv('kdd_processed.csv', index=False)
    print("✅ SUCCESS: kdd_processed.csv taiyar hai!")
except Exception as e:
    print(f"❌ Error: {e}")