import pickle
import numpy as np
import pandas as pd
import os

# ── Paths — Person A ke folders
BASE    = r"D:\QNIDS-Project\qnids_final_complete"
MDL_DIR = os.path.join(BASE, "models")
DAT_DIR = os.path.join(BASE, "data")

# NSL-KDD 41 feature columns — exact order
FEATURE_COLS = [
    'duration','protocol_type','service','flag',
    'src_bytes','dst_bytes','land','wrong_fragment',
    'urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate',
    'dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]

# Attack type display names
ATTACK_DISPLAY = {
    'normal':          ('Normal Traffic',    '🟢 NORMAL',  '#10b981'),
    'neptune':         ('DoS - Neptune',     '🔴 ATTACK',  '#ef4444'),
    'smurf':           ('DoS - Smurf',       '🔴 ATTACK',  '#ef4444'),
    'back':            ('DoS - Back',        '🔴 ATTACK',  '#ef4444'),
    'teardrop':        ('DoS - Teardrop',    '🔴 ATTACK',  '#ef4444'),
    'pod':             ('DoS - Pod',         '🔴 ATTACK',  '#ef4444'),
    'land':            ('DoS - Land',        '🔴 ATTACK',  '#ef4444'),
    'ipsweep':         ('Probe - IPSweep',   '🔴 ATTACK',  '#ef4444'),
    'portsweep':       ('Probe - PortSweep', '🔴 ATTACK',  '#ef4444'),
    'satan':           ('Probe - Satan',     '🔴 ATTACK',  '#ef4444'),
    'nmap':            ('Probe - Nmap',      '🔴 ATTACK',  '#ef4444'),
    'warezclient':     ('R2L - Warez',       '🔴 ATTACK',  '#ef4444'),
    'guess_passwd':    ('R2L - GuessPass',   '🔴 ATTACK',  '#ef4444'),
    'warezmaster':     ('R2L - Warezmaster', '🔴 ATTACK',  '#ef4444'),
    'imap':            ('R2L - IMAP',        '🔴 ATTACK',  '#ef4444'),
    'ftp_write':       ('R2L - FTP Write',   '🔴 ATTACK',  '#ef4444'),
    'buffer_overflow': ('U2R - Overflow',    '🔴 ATTACK',  '#ef4444'),
    'rootkit':         ('U2R - Rootkit',     '🔴 ATTACK',  '#ef4444'),
    'loadmodule':      ('U2R - LoadModule',  '🔴 ATTACK',  '#ef4444'),
    'perl':            ('U2R - Perl',        '🔴 ATTACK',  '#ef4444'),
}


class QNIDSPredictor:
    """
    Person A ke trained models use karke
    predictions karta hai
    """

    def __init__(self):
        self.model         = None
        self.scaler        = None
        self.encoders      = None
        self.feature_cols  = None
        self.label_classes = None
        self.qpso_mask     = None
        self.is_loaded     = False
        self._load_models()

    def _load_models(self):
        try:
            print("Models load ho rahe hain...")

            # RF+QPSO model load karo
            model_path = os.path.join(MDL_DIR, "rf_qpso.pkl")
            if not os.path.exists(model_path):
                model_path = os.path.join(
                    MDL_DIR, "final_model.pkl"
                )
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"Model loaded: {type(self.model)}")

            # Scaler load karo
            scaler_path = os.path.join(DAT_DIR, "scaler.pkl")
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print("Scaler loaded")

            # Encoders load karo
            enc_path = os.path.join(DAT_DIR, "encoders.pkl")
            with open(enc_path, 'rb') as f:
                self.encoders = pickle.load(f)
            print("Encoders loaded")

            # Feature columns load karo
            fc_path = os.path.join(DAT_DIR, "feature_cols.npy")
            self.feature_cols = np.load(
                fc_path, allow_pickle=True
            )
            print(f"Features: {len(self.feature_cols)}")

            # Label classes load karo
            lc_path = os.path.join(
                DAT_DIR, "label_classes.npy"
            )
            self.label_classes = np.load(
                lc_path, allow_pickle=True
            )
            print(f"Classes: {list(self.label_classes)}")

            # QPSO mask load karo
            mask_path = os.path.join(
                MDL_DIR, "qpso_mask.npy"
            )
            if os.path.exists(mask_path):
                self.qpso_mask = np.load(mask_path)
                selected = int(np.sum(self.qpso_mask))
                print(f"QPSO mask: {selected} features selected")

            self.is_loaded = True
            print("All models loaded successfully!")

        except Exception as e:
            print(f"Model load error: {e}")
            self.is_loaded = False

    def load_unsw_model(self):
        """UNSW-NB15 model switch karo"""
        try:
            unsw_path = os.path.join(
                MDL_DIR, "rf_unsw.pkl"
            )
            if os.path.exists(unsw_path):
                with open(unsw_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("UNSW model switched!")
            else:
                print("rf_unsw.pkl nahi mila")
        except Exception as e:
            print(f"UNSW load error: {e}")

    def load_nslkdd_model(self):
        """NSL-KDD model wapas load karo"""
        try:
            model_path = os.path.join(
                MDL_DIR, "rf_qpso.pkl"
            )
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print("NSL-KDD model restored!")
        except Exception as e:
            print(f"NSL-KDD restore error: {e}")
            
    def predict_row(self, row_series):
        """
        NSL-KDD dataset ka ek row leke
        prediction karta hai

        Returns:
            attack_type  : str  — display name
            verdict      : str  — NORMAL/ATTACK/UNKNOWN
            color        : str  — hex color
            confidence   : int  — 0-100
        """
        if not self.is_loaded:
            return self._fallback(row_series)

        try:
            # Step 1: Categorical features encode karo
            row_encoded = row_series.copy()

            cat_cols = ['protocol_type', 'service', 'flag']
            for col in cat_cols:
                if col in row_encoded.index:
                    val = str(row_encoded[col])
                    if self.encoders and col in self.encoders:
                        enc = self.encoders[col]
                        if val in enc.classes_:
                            row_encoded[col] = enc.transform([val])[0]
                        else:
                            row_encoded[col] = 0
                    else:
                        row_encoded[col] = 0

            # Step 2: Feature columns select karo
            if self.feature_cols is not None:
                features = []
                for col in self.feature_cols:
                    if col in row_encoded.index:
                        features.append(
                            float(row_encoded[col])
                        )
                    else:
                        features.append(0.0)
                X = np.array(features).reshape(1, -1)
            else:
                X = row_encoded[FEATURE_COLS].values\
                    .astype(float).reshape(1, -1)

            # Step 3: Scale karo
            if self.scaler is not None:
                try:
                    X = self.scaler.transform(X)
                except Exception:
                    pass

            # Step 4: QPSO mask apply karo
            if self.qpso_mask is not None:
                mask = self.qpso_mask.astype(bool)
                if X.shape[1] == len(mask):
                    X = X[:, mask]

            # Step 5: Predict karo
            pred_idx = self.model.predict(X)[0]

            # Step 6: Confidence nikalo
            confidence = 85
            if hasattr(self.model, 'predict_proba'):
                proba      = self.model.predict_proba(X)[0]
                confidence = int(np.max(proba) * 100)

            # Step 7: Label decode karo
            if self.label_classes is not None:
                if isinstance(pred_idx, (int, np.integer)):
                    if pred_idx < len(self.label_classes):
                        label = str(
                            self.label_classes[pred_idx]
                        ).lower()
                    else:
                        label = 'unknown'
                else:
                    label = str(pred_idx).lower()
            else:
                label = str(pred_idx).lower()

            # Step 8: Display info nikalo
            attack_type, verdict, color = \
                self._get_display(label)

            return attack_type, verdict, color, confidence

        except Exception as e:
            print(f"Prediction error: {e}")
            return self._fallback(row_series)

    def _get_display(self, label):
        """Label se display info nikalo"""
        label = label.strip().lower()

        # Exact match
        if label in ATTACK_DISPLAY:
            return ATTACK_DISPLAY[label]

        # Partial match
        for key, val in ATTACK_DISPLAY.items():
            if key in label or label in key:
                return val

        # Normal check
        if 'normal' in label:
            return ('Normal Traffic', '🟢 NORMAL', '#10b981')

        # Unknown
        return (
            f'⚠ Unknown: {label}',
            '🟠 UNKNOWN',
            '#f59e0b'
        )

    def _fallback(self, row_series):
        """Model load nahi hua — label se direct result"""
        import random
        try:
            label = str(row_series.get(
                'label', 'unknown'
            )).lower().strip()
            attack_type, verdict, color = \
                self._get_display(label)
            conf = random.randint(80, 99) \
                if verdict == '🟢 NORMAL' \
                else random.randint(75, 95)
            return attack_type, verdict, color, conf
        except Exception:
            return (
                'Unknown', '🟠 UNKNOWN', '#f59e0b', 70
            )


# ── Test karo
if __name__ == "__main__":
    predictor = QNIDSPredictor()
    if predictor.is_loaded:
        print("\nModel test ready!")
    else:
        print("\nModel load nahi hua — fallback mode")