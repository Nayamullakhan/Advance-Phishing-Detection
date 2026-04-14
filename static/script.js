document.getElementById('check-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    if (!url) return;

    // UI States
    const btn = document.getElementById('check-btn');
    const resultsSection = document.getElementById('results-section');
    const errorDiv = document.getElementById('error-message');
    
    btn.classList.add('loading');
    btn.disabled = true;
    resultsSection.classList.add('hidden');
    errorDiv.classList.add('hidden');

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const data = await response.json();

        if (data.error) {
            throw new Error(data.error);
        }

        // Update UI with results
        updateResults(data);
        resultsSection.classList.remove('hidden');

    } catch (error) {
        errorDiv.textContent = error.message || 'An error occurred while analyzing the URL.';
        errorDiv.classList.remove('hidden');
    } finally {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});

function updateResults(data) {
    const isPhishing = data.prediction === 1; // 1 for Phishing, 0 for Legitimate
    const riskScore = (data.risk_score * 100).toFixed(1);
    
    // Prediction Badge
    const badge = document.getElementById('prediction-badge');
    badge.textContent = isPhishing ? 'Phishing' : 'Legitimate';
    badge.className = 'status-badge ' + (isPhishing ? 'phishing' : 'safe');
    
    const desc = document.getElementById('prediction-desc');
    desc.textContent = isPhishing 
        ? 'High risk indicators detected.' 
        : 'No phishing indicators detected.';

    // Risk Score
    const scoreText = document.getElementById('score-text');
    scoreText.textContent = `${riskScore}%`;
    
    const circle = document.getElementById('score-circle-path');
    const color = isPhishing ? '#ef4444' : '#10b981';
    circle.style.stroke = color;
    circle.style.strokeDasharray = `${riskScore}, 100`;

    // SHAP Plot
    const shapImage = document.getElementById('shap-plot');
    if (data.shap_plot_url) {
        // Add timestamp to prevent caching
        shapImage.src = data.shap_plot_url + '?t=' + new Date().getTime();
    }
}
