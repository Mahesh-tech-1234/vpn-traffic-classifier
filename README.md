# VPN vs Non-VPN Traffic Classification Dashboard

A single-page web dashboard for classifying network traffic as VPN or Non-VPN using three deep learning models (CNN, LSTM, NIN). Built with vanilla HTML, CSS, JavaScript, and a Flask API. Uses the ISCX dataset.

## Features

- **Login / Registration**: Simple auth gate. Register or sign in to access the dashboard (credentials stored in browser).
- **System Overview**: Real data from ISCX dataset — total flows, VPN/Non-VPN percentages, flow density chart, traffic distribution, traffic type analysis. Cached for fast loading.
- **Live Capture**: Simulates live network traffic by randomly loading flows from the dataset every ~2.5s. Captures and analyzes in real-time with CNN, LSTM, NIN.
- **Live Classification**: Load real sample or enter flow parameters; get CNN, LSTM, and NIN predictions with confidence.
- **CSV Upload**: Bulk classification with preview and downloadable results.
- **Metrics Dashboard**: Model accuracy, precision, recall, F1-score, confusion matrices, and charts (radar, bar).
- **Threat & Anomaly Detection**: Upload CSV to detect anomalous flows (low confidence or model disagreement). Global threat gauge, anomaly timeline, and critical anomalies list.
- **Light/Dark Mode**: Toggle theme with preference persisted in `localStorage`.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Place Model Files

Put trained models in the `models/` folder:

```
models/
├── cnn_vpn_model.keras
├── lstm_vpn_model.keras
├── nin_vpn_model.keras
└── scaler.pkl
```

Startup will fail with a clear error if any are missing.

### 3. Run the Application

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser. You'll be redirected to `/login` to register or sign in first.

## API Endpoints

| Method | Endpoint           | Description                              |
|--------|--------------------|------------------------------------------|
| GET    | `/`                | Serves dashboard (index.html)            |
| GET    | `/status`          | Model status (CNN, LSTM, NIN)             |
| GET    | `/sample`          | Random flow from ISCX_Data.csv            |
| POST   | `/predict`         | Single prediction (JSON body)             |
| POST   | `/predict-bulk`    | Bulk prediction (multipart CSV)           |
| POST   | `/detect-anomalies`| Anomaly detection (multipart CSV)         |
| GET    | `/metrics`         | Model metrics (accuracy, precision, etc.) |
| GET    | `/overview`        | System overview stats (cached)            |

## Project Structure

```
vpnnonvpn/
├── app.py              # Flask API
├── index.html          # Dashboard UI (requires login)
├── login.html          # Login & registration page
├── styles.css          # Styles + theme
├── app.js              # Frontend logic + Chart.js
├── requirements.txt
├── README.md
├── models/             # Trained models (required)
│   ├── cnn_vpn_model.keras
│   ├── lstm_vpn_model.keras
│   ├── nin_vpn_model.keras
│   └── scaler.pkl
├── ISCX_Data.csv       # Main dataset (for overview + samples)
├── ISCX_sample_10x10.csv
├── ISCX_sample_10rows_full.csv
├── trainingcode.txt    # Model training code
└── traininglogs.txt   # Training logs
```

## Tech Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript, Chart.js, Poppins font
- **Backend**: Flask, Flask-CORS
- **ML**: TensorFlow/Keras, scikit-learn, pandas, numpy

## License

MIT
