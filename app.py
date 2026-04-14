import os
import sys
import pickle
import joblib
import numpy as np
import shap
import matplotlib
matplotlib.use('Agg') # Non-interactive backend
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, jsonify, url_for
from feature_extractor import extract_features, FEATURE_NAMES

app = Flask(__name__)

# Load models
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
TOP_FEATURES_PATH = os.path.join(MODEL_DIR, 'top_features.pkl')
MODEL_PATH = os.path.join(MODEL_DIR, 'xgb_phishing_model.pkl')
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, 'feature_names.pkl')

print("Loading models...")
try:
    scaler = joblib.load(SCALER_PATH)
    top_features_indices = joblib.load(TOP_FEATURES_PATH) # Expected: numpy array of indices
    model = joblib.load(MODEL_PATH)
    feature_names_full = joblib.load(FEATURE_NAMES_PATH)
    
    # Create SHAP explainer
    # Note: TreeExplainer is efficient for XGBoost
    explainer = shap.TreeExplainer(model)
    
    print("Models loaded successfully.")
    
except Exception as e:
    print(f"Error loading models: {e}")
    sys.exit(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        # 1. Extract Features
        print(f"Extracting features for: {url}")
        features_list = extract_features(url)
        
        # 2. Scale Features
        # Reshape to 1 sample, N features (111)
        features_array = np.array(features_list).reshape(1, -1)
        features_scaled = scaler.transform(features_array)
        
        # 3. Select Top Features
        # top_features_indices is int64 array of indices
        features_selected = features_scaled[:, top_features_indices]
        
        # 4. Predict
        prediction = model.predict(features_selected)[0] # 0 or 1
        prediction_prob = model.predict_proba(features_selected)[0][1] # Probability of class 1 (Phishing)
        
        # 5. SHAP Explanation
        shap_values = explainer.shap_values(features_selected)
        
        # Mapping feature names for the plot
        # We need the names of the *selected* features
        # feature_names_full is list of 111 names
        selected_feature_names = [feature_names_full[i] for i in top_features_indices]
        
        # Generate plot
        plt.figure()
        # Waterplot expects shap_values[0] for single sample and feature values
        # shap.plots.waterfall(shap.Explanation(...))
        # Or simpler legacy force_plot? Waterfall is better for local explanation.
        # But shap.plots.waterfall requires an Explanation object.
        
        # Construct Explanation object
        # base_values = explainer.expected_value
        # If binary classification, expected_value might be log odds.
        
        # Simple bar plot of top contributing features for this instance
        # manual plotting might be safer given SHAP version differences
        
        # Let's try shap.plots.waterfall first if using new SHAP version, 
        # but safely fallback to bar or summary.
        # Actually, let's just make a simple bar chart of the top 5 absolute shap values 
        # to ensure stability and "explainability".
        
        # Creating a bar chart of feature contributions
        # shap_values[0] is array of 20 values
        vals = shap_values[0]
        abs_vals = np.abs(vals)
        sorted_idx = np.argsort(abs_vals)[::-1] # Descending order
        
        top_n = 10
        top_indices = sorted_idx[:top_n]
        top_vals = vals[top_indices]
        top_names = [selected_feature_names[i] for i in top_indices]
        
        plt.figure(figsize=(10, 6))
        colors = ['red' if v > 0 else 'green' for v in top_vals]
        y_pos = np.arange(len(top_names))
        
        plt.barh(y_pos, top_vals, align='center', color=colors)
        plt.yticks(y_pos, top_names)
        plt.xlabel('SHAP Value (Impact on Model Output)')
        plt.title('Top Feature Contributions')
        plt.gca().invert_yaxis() # Highest impact on top
        plt.tight_layout()
        
        # Save plot
        plot_filename = f'shap_plot_{os.urandom(4).hex()}.png'
        plot_path = os.path.join('static', plot_filename)
        # Clear old plots? Maybe later.
        plt.savefig(os.path.join(os.path.dirname(__file__), plot_path))
        plt.close()
        
        return jsonify({
            'prediction': int(prediction),
            'risk_score': float(prediction_prob),
            'shap_plot_url': url_for('static', filename=plot_filename)
        })

    except Exception as e:
        print(f"Error during inference: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
