# 🔐 Pixels with Purpose — Steganography Working Model
### SMIT CSE Group 4 | PBL Project | Dr. Samarendra Nath Sur

---

## 📦 Project Structure

```
steganography/
├── app.py               ← Flask backend (all steganography logic)
├── requirements.txt     ← Python dependencies
├── templates/
│   └── index.html       ← Full web UI
└── README.md
```

---

## 🚀 Setup & Run (Step-by-Step)

### Step 1 — Install Python (if not installed)
Download Python 3.10+ from https://python.org

### Step 2 — Install dependencies
Open terminal in the project folder and run:
```bash
pip install -r requirements.txt
```

### Step 3 — Run the app
```bash
python app.py
```

### Step 4 — Open in browser
Visit: **http://localhost:5000**

---

## 🌐 Permanent Public Deployment (No Expiring Link)

Quick tunnel links expire. For a stable link, deploy on Render.

### Files already added for deployment
- [Procfile](Procfile)
- [render.yaml](render.yaml)
- [requirements.txt](requirements.txt) includes gunicorn

### Deploy steps (Render)
1. Push this project to a GitHub repository.
2. Open Render dashboard and create a new Web Service from your GitHub repo.
3. Render will auto-detect [render.yaml](render.yaml). If asked manually:
  - Build Command: pip install -r requirements.txt
  - Start Command: gunicorn app:app
4. Deploy.
5. Share the generated Render URL (this will be stable and HTTPS).

### Notes
- Free plans may sleep after inactivity, but URL remains the same.
- You can later attach a custom domain for a cleaner link.

---

## 🛠️ Features

### 🔒 Tab 1: Embed Message
- Upload any PNG/JPG image as the **cover image**
- Type your **secret text message**
- Click **Embed** → generates a stego image
- View **PSNR** and **MSE** quality metrics
- Download the stego image as PNG

### 🔓 Tab 2: Extract Message
- Upload the stego image created by this tool
- Click **Extract** → reveals the hidden message

### 🔍 Tab 3: Steganalysis Tool
- Upload any image (clean OR stego)
- Runs **Chi-Square Attack** (statistical steganalysis)
- Shows **LSB Plane Visualization**
- Displays **risk level** (High / Medium / Low)
- Auto-extracts hidden message if found

### 📖 Tab 4: How It Works
- Full explanation of LSB steganography
- Chi-Square steganalysis theory
- Quality metrics explained

---

## 🧪 Technical Details

### LSB Steganography Algorithm
```
For each bit of the secret message:
  pixel[i] = (pixel[i] & 0xFE) | bit
  
This sets the least significant bit of each pixel value.
A pixel value of 200 (11001000) might become 201 (11001001).
Difference: only 1 out of 255 → invisible to human eye.
```

### Chi-Square Steganalysis
```
H₀: Image is natural (no embedding)
H₁: Image has been steganographically modified

Test statistic: χ² = Σ (Observed - Expected)² / Expected
If p-value < 0.05 → Reject H₀ → Hidden data detected
```

### Quality Metrics
| Metric | Formula | Threshold |
|--------|---------|-----------|
| MSE | Σ(orig - stego)² / n | < 1.0 good |
| PSNR | 20·log₁₀(255/√MSE) | > 40 dB good |

---

## 👥 Team
- Roushan Srivastava (202400325)
- Aditya Raj Singh (202400564)
- Gunnidhi Singhi (202400177)
- Shivang Mondal (202400327)
- Alan Chettri (202542503)

**Supervisor:** Dr. Samarendra Nath Sur  
**Institution:** Sikkim Manipal Institute of Technology
