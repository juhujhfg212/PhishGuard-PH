# ============================================
# PhishGuard PH v7 - Welcome Dashboard + Analyzer
# CpE Elective 1 Final Project
# ============================================

import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# ============================================
# PAGE CONFIG
# ============================================
st.set_page_config(
    page_title="PhishGuard PH",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# ============================================
# CUSTOM CSS
# ============================================
st.markdown("""
<style>
    .hero {
        text-align: center;
        padding: 40px 20px;
        background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
        border-radius: 20px;
        color: white;
        margin-bottom: 20px;
    }
    .hero h1 {
        font-size: 48px;
        margin-bottom: 10px;
    }
    .hero p {
        font-size: 18px;
        opacity: 0.9;
    }
    .layer-card {
        padding: 25px 20px;
        border-radius: 15px;
        text-align: center;
        color: white;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .layer1 { background: linear-gradient(135deg, #667eea, #764ba2); }
    .layer2 { background: linear-gradient(135deg, #f093fb, #f5576c); }
    .layer3 { background: linear-gradient(135deg, #4facfe, #00f2fe); }
    .stat-card {
        padding: 20px;
        border-radius: 12px;
        text-align: center;
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        color: white;
        box-shadow: 0 4px 10px rgba(0,0,0,0.2);
    }
    .stat-number {
        font-size: 36px;
        font-weight: bold;
        color: #00f2fe;
    }
    .stat-label {
        font-size: 14px;
        color: #ccc;
    }
    }
    .verdict-box {
        padding: 30px 20px;
        border-radius: 15px;
        text-align: center;
        margin: 15px 0px;
    }
    .safe-box {
        background-color: #28a745;
        border: 4px solid #1e7e34;
        color: white;
    }
    .danger-box {
        background-color: #dc3545;
        border: 4px solid #a71d2a;
        color: white;
    }
    .feature-row {
        display: flex;
        gap: 12px;
        margin: 8px 0;
    }
    .feature-item {
        flex: 1;
        padding: 14px 8px;
        background: linear-gradient(135deg, #0f3460, #16213e);
        border-radius: 10px;
        text-align: center;
        color: white;
        font-weight: bold;
        font-size: 15px;
        box-shadow: 0 3px 8px rgba(0,0,0,0.2);
        border: 2px solid #4facfe;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# LOAD MODEL & FEATURES
# ============================================
@st.cache_resource
def load_model():
    return joblib.load("phishguard_model.pkl")

@st.cache_resource
def load_features():
    return joblib.load("feature_list.pkl")

model = load_model()
feature_names = load_features()

# ============================================
# KNOWN BRANDS
# ============================================
REAL_DOMAINS = {
    'gcash': 'gcash.com',
    'maya': 'maya.ph',
    'bdo': 'bdo.com.ph',
    'bpi': 'bpi.com.ph',
    'metrobank': 'metrobank.com.ph',
    'shopee': 'shopee.ph',
    'lazada': 'lazada.com.ph',
    'grab': 'grab.com',
    'globe': 'globe.com.ph',
    'smart': 'smart.com.ph',
    'paypal': 'paypal.com',
    'facebook': 'facebook.com',
    'google': 'google.com',
    'netflix': 'netflix.com',
    'philhealth': 'philhealth.gov.ph',
    'sss': 'sss.gov.ph',
    'pagibig': 'pagibigfund.gov.ph',
}

# ============================================
# SESSION STATE (page navigation)
# ============================================
if 'page' not in st.session_state:
    st.session_state.page = 'welcome'
if 'loading' not in st.session_state:
    st.session_state.loading = False

# ============================================
# VALIDATION
# ============================================
def validate_url(url):
    if not url or not url.strip():
        return False, "Please enter a URL to analyze."
    url = url.strip()
    if len(url) < 5:
        return False, "URL is too short."
    if len(url) > 2000:
        return False, "URL is too long (max 2000 characters)."
    if not any(c.isalnum() for c in url):
        return False, "URL contains no valid characters."
    clean = url if url.startswith('http') else 'http://' + url
    try:
        parsed = urlparse(clean)
        host = parsed.hostname or ''
        if not host:
            return False, "Could not extract a domain."
        if '.' not in host and not re.match(
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
            return False, "URL does not contain a valid domain."
    except Exception:
        return False, "URL format is invalid."
    dangerous = ['<script', 'javascript:', 'onerror=',
                 'onload=', '<img', '<svg']
    for d in dangerous:
        if d in url.lower():
            return False, "URL contains dangerous code."
    return True, ""

# ============================================
# CLONE DETECTOR (with @ split fix!)
# ============================================
def detect_clones(domain, full_url=""):
    clone_flags = []
    domain_lower = domain.lower()

    # --- @ SPLIT ATTACK ---
    if '@' in full_url:
        try:
            p = urlparse(full_url if full_url.startswith(
                'http') else 'http://' + full_url)
            username = (p.username or '').lower()
            hostname = (p.hostname or '').lower()
            combined = username + hostname
            combined_a = username + 'a' + hostname
            for brand, real_domain in REAL_DOMAINS.items():
                real_base = real_domain.split('.')[0]
                if real_base in combined or real_base in combined_a:
                    clone_flags.append(
                        f"@ split attack: '{username}@{hostname}' "
                        f"mimics '{brand}'")
                    break
            if not clone_flags and len(username) >= 3:
                for brand, real_domain in REAL_DOMAINS.items():
                    real_base = real_domain.split('.')[0]
                    test = username + hostname.split('.')[0]
                    matches = sum(
                        1 for a, b in zip(test, real_base) if a == b)
                    sim = matches / max(len(test), len(real_base))
                    if sim >= 0.70 and abs(
                            len(test) - len(real_base)) <= 2:
                        clone_flags.append(
                            f"@ split attack: '{username}@{hostname}' "
                            f"is {sim:.0%} similar to '{brand}'")
                        break
        except:
            pass

    # --- CHARACTER SUBSTITUTION ---
    swaps = {
        '0': 'o', '1': 'l', '4': 'a', '3': 'e',
        '5': 's', '7': 't', '8': 'b', '9': 'g',
    }
    normalized = domain_lower
    for fake, real in swaps.items():
        normalized = normalized.replace(fake, real)
    normalized = normalized.replace('rn', 'm')
    normalized = normalized.replace('cl', 'd')
    normalized = normalized.replace('vv', 'w')

    if normalized != domain_lower:
        for brand, real_domain in REAL_DOMAINS.items():
            real_base = real_domain.split('.')[0]
            if real_base in normalized and real_base not in domain_lower:
                clone_flags.append(
                    f"Character substitution: '{domain_lower}' "
                    f"mimics '{real_base}'")
                break
        if not clone_flags:
            clone_flags.append(
                "Suspicious character substitution detected")

    # --- TYPO-SQUATTING ---
    domain_parts = domain_lower.replace('.com', '').replace(
        '.ph', '').replace('.org', '').replace(
        '.net', '').replace('.gov', '').split('.')
    for brand, real_domain in REAL_DOMAINS.items():
        real_base = real_domain.split('.')[0]
        for part in domain_parts:
            if part == real_base:
                continue
            if len(part) >= 3 and len(real_base) >= 3:
                matches = sum(
                    1 for a, b in zip(part, real_base) if a == b)
                similarity = matches / max(
                    len(part), len(real_base))
                if 0.70 <= similarity < 1.0 and abs(
                        len(part) - len(real_base)) <= 2:
                    clone_flags.append(
                        f"Typo-squatting: '{part}' is "
                        f"{similarity:.0%} similar to '{real_base}'")

    # --- BRAND SPOOFING ---
    for brand, real_domain in REAL_DOMAINS.items():
        if brand in domain_lower:
            if not domain_lower.endswith(real_domain):
                main = '.'.join(domain_lower.split('.')[-2:])
                clone_flags.append(
                    f"Brand spoofing: '{brand}' found but "
                    f"domain is {main}, not {real_domain}")

    return clone_flags

# ============================================
# FEATURE EXTRACTION
# ============================================
def extract_features(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ''
        netloc = parsed.netloc or ''
    except:
        return None, []

    features = {}
    red_flags = []

    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        features['having_ip_address'] = -1
        red_flags.append("Uses IP address instead of domain")
    else:
        features['having_ip_address'] = 1

    if len(url) < 54:
        features['url_length'] = 1
    elif len(url) <= 75:
        features['url_length'] = 0
        red_flags.append("URL is moderately long")
    else:
        features['url_length'] = -1
        red_flags.append("URL is suspiciously long (>75 chars)")

    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co',
                  'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
    is_shortener = any(s in url.lower() for s in shorteners)
    if is_shortener:
        features['shortining_service'] = -1
        red_flags.append("Uses URL shortener (hides destination)")
    else:
        features['shortining_service'] = 1

    if '@' in url:
        features['having_at_symbol'] = -1
        red_flags.append("Contains '@' symbol (hiding trick)")
    else:
        features['having_at_symbol'] = 1

    if '//' in url[7:]:
        features['double_slash_redirecting'] = -1
        red_flags.append("Double-slash redirect detected")
    else:
        features['double_slash_redirecting'] = 1

    if '-' in netloc:
        features['prefix_suffix'] = -1
        red_flags.append("Hyphens in domain (impersonation)")
    else:
        features['prefix_suffix'] = 1

    dots = netloc.count('.')
    if dots <= 1:
        features['having_sub_domain'] = 1
    elif dots == 2:
        features['having_sub_domain'] = 0
        red_flags.append("Multiple subdomains")
    else:
        features['having_sub_domain'] = -1
        red_flags.append("Too many subdomains")

    if url.startswith('https'):
        features['sslfinal_state'] = 1
    else:
        features['sslfinal_state'] = -1
        red_flags.append("No HTTPS encryption")

    try:
        port = parsed.port
        if port and port not in [80, 443]:
            features['port'] = -1
            red_flags.append("Unusual port number")
        else:
            features['port'] = 1
    except:
        features['port'] = 1

    if 'https' in domain:
        features['https_token'] = -1
        red_flags.append("Fake 'https' in domain name")
    else:
        features['https_token'] = 1

    if 'mailto:' in url.lower():
        features['submitting_to_email'] = -1
        red_flags.append("Submits data via email")
    else:
        features['submitting_to_email'] = 1

    features['abnormal_url'] = 1

    if url.count('//') > 1:
        features['redirect'] = -1
        red_flags.append("Multiple redirects")
    else:
        features['redirect'] = 1

    if 'onmouseover' in url.lower():
        features['on_mouseover'] = -1
        red_flags.append("Mouseover script detected")
    else:
        features['on_mouseover'] = 1

    sus_kw = ['login', 'verify', 'secure', 'update',
              'password', 'confirm', 'authenticate',
              'credential', 'signin', 'account']
    found_kw = [kw for kw in sus_kw if kw in url.lower()]
    if len(found_kw) >= 2:
        red_flags.append(f"Keywords: {', '.join(found_kw)}")

    ph_brands = list(REAL_DOMAINS.keys())
    found_brands = [b for b in ph_brands if b in url.lower()]
    if is_shortener and found_brands:
        red_flags.append(
            f"Shortener + brand '{found_brands[0]}'")
    if found_brands:
        brand = found_brands[0]
        real = REAL_DOMAINS.get(brand, '')
        if real and real not in domain:
            red_flags.append(
                f"'{brand}' mentioned but domain != {real}")

    row = [features.get(name, 1) for name in feature_names]
    return pd.DataFrame([row], columns=feature_names), red_flags

# ============================================
# PAGE 1: WELCOME DASHBOARD
# ============================================
if st.session_state.page == 'welcome':

    # --- HERO SECTION ---
    st.markdown("""
    <div class="hero">
        <h1>🛡️ PhishGuard PH</h1>
        <p>Triple-Layer Offline Phishing Detector for Filipinos</p>
        <p style="font-size: 14px; opacity: 0.7;">
        AI-Powered | No Internet Required | 100% Private</p>
    </div>
    """, unsafe_allow_html=True)

    # --- STATS ---
    st.markdown("### 📊 By the Numbers")
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">11,055</div>
            <div class="stat-label">URLs Trained</div>
        </div>
        """, unsafe_allow_html=True)
    with s2:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">91.04%</div>
            <div class="stat-label">AI Accuracy</div>
        </div>
        """, unsafe_allow_html=True)
    with s3:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">14</div>
            <div class="stat-label">Features Analyzed</div>
        </div>
        """, unsafe_allow_html=True)
    with s4:
        st.markdown("""
        <div class="stat-card">
            <div class="stat-number">17</div>
            <div class="stat-label">Brands Protected</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # --- HOW IT WORKS ---
    st.markdown("### 🔍 How It Works")
    st.markdown(
        "PhishGuard uses **3 layers of defense** to catch "
        "phishing attacks that other tools miss:")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
        <div class="layer-card layer1">
            <h2>🤖</h2>
            <h3>Layer 1</h3>
            <h4>AI Model</h4>
            <p>Random Forest classifier trained on 11,055 real
            phishing URLs. Analyzes 14 URL characteristics.</p>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="layer-card layer2">
            <h2>📏</h2>
            <h3>Layer 2</h3>
            <h4>Rule Engine</h4>
            <p>Checks for known phishing patterns: shorteners,
            suspicious keywords, missing HTTPS, and more.</p>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="layer-card layer3">
            <h2>🕵️</h2>
            <h3>Layer 3</h3>
            <h4>Clone Detector</h4>
            <p>Catches visual clone attacks like gc4sh.com,
            payp@l.com, and rnaya.ph that fool human eyes.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # --- PROTECTED BRANDS ---
    st.markdown("### 🏢 Protected Filipino Brands")
    st.markdown("""
    <div class="feature-row">
        <div class="feature-item">💚 GCash</div>
        <div class="feature-item">💙 Maya</div>
        <div class="feature-item">🏦 BDO</div>
        <div class="feature-item">🏦 BPI</div>
        <div class="feature-item">🏦 Metrobank</div>
    </div>
    <div class="feature-row">
        <div class="feature-item">🛒 Shopee</div>
        <div class="feature-item">🛒 Lazada</div>
        <div class="feature-item">🚗 Grab</div>
        <div class="feature-item">📱 Globe</div>
        <div class="feature-item">📱 Smart</div>
    </div>
    <div class="feature-row">
        <div class="feature-item">🏥 PhilHealth</div>
        <div class="feature-item">🏛️ SSS</div>
        <div class="feature-item">🏠 Pag-IBIG</div>
        <div class="feature-item">💳 PayPal</div>
        <div class="feature-item">🌐 + more</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("")

    # --- WHY OFFLINE ---
    st.markdown("### 🔒 Why Offline?")
    st.markdown("""
    | Feature | PhishGuard PH | Online Tools |
    |---------|--------------|-------------|
    | Internet Required | ❌ No | ✅ Yes |
    | Your Data Stays Private | ✅ Yes | ❌ No |
    | Works During Outages | ✅ Yes | ❌ No |
    | No API Keys Needed | ✅ Yes | ❌ No |
    | Free Forever | ✅ Yes | ❌ Paid tiers |
    """)

    st.markdown("")

        # --- START BUTTON ---
    st.markdown("---")
    if st.button(
        "🚀  Start Scanning URLs",
        type="primary",
        use_container_width=True
    ):
        st.session_state.loading = True
        st.rerun()

    # --- LOADING ANIMATION ---
    if st.session_state.get('loading', False):
        import time

        # Clear the page
        st.markdown("""
        <div style="text-align:center; padding:80px 20px;">
            <h1>🛡️</h1>
        </div>
        """, unsafe_allow_html=True)

        # Step 1
        with st.spinner("🔄 Loading AI Model..."):
            time.sleep(1.2)

        # Step 2
        with st.spinner("🔄 Loading Rule Engine..."):
            time.sleep(0.8)

        # Step 3
        with st.spinner("🔄 Loading Clone Detector..."):
            time.sleep(0.8)

        # Step 4
        with st.spinner("🔄 Loading Brand Database (17 brands)..."):
            time.sleep(0.6)

        # Step 5
        with st.spinner("🔄 Preparing Offline Environment..."):
            time.sleep(0.6)

        # Progress bar
        progress = st.progress(0, text="Initializing PhishGuard PH...")
        for i in range(101):
            time.sleep(0.02)
            progress.progress(i, text=f"Initializing PhishGuard PH... {i}%")

        time.sleep(0.5)

        # Done!
        st.session_state.loading = False
        st.session_state.page = 'analyzer'
        st.rerun()

    st.markdown("")
    st.markdown(
        "<div style='text-align:center; color:#999; "
        "font-size:12px;'>"
        "PhishGuard PH v7 | CpE Elective 1 Final Project | "
        "100% Offline</div>",
        unsafe_allow_html=True
    )

# ============================================
# PAGE 2: URL ANALYZER
# ============================================
elif st.session_state.page == 'analyzer':

    # --- Back Button ---
    if st.button("⬅️ Back to Dashboard"):
        st.session_state.page = 'welcome'
        st.rerun()

    st.markdown("""
    <div style="text-align:center; padding: 15px 0;">
        <h1>🛡️ PhishGuard PH</h1>
        <p style="color:#666;">Triple-Layer URL Analyzer</p>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    # --- Input ---
    st.markdown("#### 🔗 Enter URL to Analyze")
    url_input = st.text_input(
        label="URL",
        placeholder="e.g. http://gc4sh.com/login",
        label_visibility="collapsed",
        key="url_input"
    )

    col_btn, col_clear = st.columns([3, 1])
    with col_btn:
        analyze_clicked = st.button(
            "🔍  Analyze URL",
            type="primary",
            use_container_width=True
        )
    with col_clear:
        if st.button("🗑️ Clear", use_container_width=True):
            st.rerun()

    # --- Analysis ---
    if analyze_clicked:
        is_valid, error_msg = validate_url(url_input)

        if not is_valid:
            st.markdown("---")
            st.error(f"⚠️ **Invalid Input:** {error_msg}")
            st.info(
                "💡 **Tip:** Enter a full URL like "
                "`http://example.com`"
            )
        else:
            clean_url = url_input.strip()

            with st.spinner("Running triple-layer analysis..."):
                features_df, rule_flags = extract_features(
                    clean_url)

                if features_df is None:
                    st.error("❌ Could not parse the URL.")
                else:
                    # Layer 1: ML
                    ml_pred = model.predict(features_df)[0]
                    ml_prob = model.predict_proba(
                        features_df)[0]
                    ml_phish = ml_prob[0] * 100
                    ml_says = ml_pred == 0

                    # Layer 2: Rules
                    rule_count = len(rule_flags)
                    rule_says = rule_count >= 3

                    # Layer 3: Clone
                    try:
                        p = urlparse(
                            clean_url if clean_url.startswith(
                            'http') else 'http://' + clean_url)
                        dom = p.hostname or ''
                    except:
                        dom = ''
                    clone_flags = detect_clones(dom, clean_url)
                    clone_says = len(clone_flags) > 0

                    # Combined
                    is_phishing = (ml_says or rule_says
                                   or clone_says)

                    st.markdown("---")

                    # Verdict
                    if is_phishing:
                        st.markdown("""
                        <div class="verdict-box danger-box">
                            <h2>🚨 DANGER: LIKELY PHISHING!</h2>
                            <p>DO NOT click this link or enter
                            any personal information!</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="verdict-box safe-box">
                            <h2>✅ URL APPEARS SAFE</h2>
                            <p>No major threats detected.
                            Stay vigilant!</p>
                        </div>
                        """, unsafe_allow_html=True)

                    st.markdown("")

                    # Three Cards
                    st.markdown("#### 📊 Analysis Breakdown")

                    ai_bg = "#dc3545" if ml_says else "#198754"
                    ai_text = "PHISHING" if ml_says else "SAFE"
                    ai_val = f"{ml_phish:.1f}%"

                    rule_bg = ("#dc3545" if rule_says else
                               "#fd7e14" if rule_count >= 2
                               else "#198754")
                    rule_text = ("DANGER" if rule_says else
                                 "WARNING" if rule_count >= 2
                                 else "NORMAL")
                    rule_val = f"{rule_count} flags"

                    clone_bg = ("#dc3545" if clone_says
                                else "#198754")
                    clone_text = ("CLONE FOUND!" if clone_says
                                  else "CLEAN")
                    clone_val = f"{len(clone_flags)} clones"

                    st.markdown(f"""
                    <div style="display:flex; gap:15px;
                         margin:15px 0;">
                        <div style="flex:1; background:{ai_bg};
                             color:white; padding:20px;
                             border-radius:12px; text-align:center;
                             box-shadow:0 4px 8px
                             rgba(0,0,0,0.2);">
                            <div style="font-size:14px;
                                 opacity:0.9;">🤖 AI Model</div>
                            <div style="font-size:32px;
                                 font-weight:bold;
                                 margin:8px 0;">{ai_val}</div>
                            <div style="font-size:16px;
                                 font-weight:bold;
                                 background:rgba(255,255,255,0.25);
                                 padding:4px 12px;
                                 border-radius:20px;
                                 display:inline-block;">
                                 {ai_text}</div>
                        </div>
                        <div style="flex:1; background:{rule_bg};
                             color:white; padding:20px;
                             border-radius:12px; text-align:center;
                             box-shadow:0 4px 8px
                             rgba(0,0,0,0.2);">
                            <div style="font-size:14px;
                                 opacity:0.9;">📏 Rule Engine</div>
                            <div style="font-size:32px;
                                 font-weight:bold;
                                 margin:8px 0;">{rule_val}</div>
                            <div style="font-size:16px;
                                 font-weight:bold;
                                 background:rgba(255,255,255,0.25);
                                 padding:4px 12px;
                                 border-radius:20px;
                                 display:inline-block;">
                                 {rule_text}</div>
                        </div>
                        <div style="flex:1; background:{clone_bg};
                             color:white; padding:20px;
                             border-radius:12px; text-align:center;
                             box-shadow:0 4px 8px
                             rgba(0,0,0,0.2);">
                            <div style="font-size:14px;
                                 opacity:0.9;">🕵️ Clone</div>
                            <div style="font-size:32px;
                                 font-weight:bold;
                                 margin:8px 0;">{clone_val}</div>
                            <div style="font-size:16px;
                                 font-weight:bold;
                                 background:rgba(255,255,255,0.25);
                                 padding:4px 12px;
                                 border-radius:20px;
                                 display:inline-block;">
                                 {clone_text}</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    # Flags
                    all_flags = rule_flags + clone_flags
                    st.markdown(
                        f"#### 🚩 Detected Issues "
                        f"({len(all_flags)})")

                    if not all_flags:
                        st.markdown("""
                        <div style="padding:15px 20px;
                             background:#198754; color:white;
                             border-radius:8px; font-size:16px;
                             font-weight:bold; margin:8px 0;">
                            ✅ No suspicious characteristics!
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        for i, flag in enumerate(all_flags, 1):
                            if flag in clone_flags:
                                st.markdown(f"""
                                <div style="padding:12px 16px;
                                     background:#f8d7da;
                                     color:#842029;
                                     border-left:6px solid #dc3545;
                                     border-radius:6px;
                                     font-size:15px;
                                     margin:6px 0;
                                     font-weight:500;">
                                    🕵️ <b>CLONE:</b> {flag}
                                </div>
                                """, unsafe_allow_html=True)
                            else:
                                st.markdown(f"""
                                <div style="padding:12px 16px;
                                     background:#fff3cd;
                                     color:#664d03;
                                     border-left:6px solid #ff9800;
                                     border-radius:6px;
                                     font-size:15px;
                                     margin:6px 0;
                                     font-weight:500;">
                                    ⚠️ {flag}
                                </div>
                                """, unsafe_allow_html=True)

                    # Safety Tips
                    if is_phishing:
                        st.markdown("")
                        st.markdown(
                            "#### 🛡️ What You Should Do")
                        st.markdown("""
                        | ❌ DO NOT | ✅ DO |
                        |-----------|-------|
                        | Click the link | Report as spam |
                        | Enter password | Delete the message |
                        | Share OTP code | Contact real company |
                        | Download files | Warn friends & family |
                        """)

                    # Technical
                    st.markdown("")
                    with st.expander("🔧 Technical Details"):
                        tc1, tc2 = st.columns(2)
                        with tc1:
                            st.write("**Detection:** Triple-Layer")
                            st.write("**ML Model:** Random Forest")
                            st.write("**Accuracy:** 91.04%")
                            st.write("**Training:** 11,055 URLs")
                        with tc2:
                            st.write("**Features:** 14 URL-based")
                            st.write("**Clone DB:** 17 brands")
                            triggered = []
                            if ml_says:
                                triggered.append("AI")
                            if rule_says:
                                triggered.append("Rules")
                            if clone_says:
                                triggered.append("Clone")
                            st.write(
                                f"**Triggered:** "
                                f"{', '.join(triggered)}")
                            st.write(
                                f"**Phish Prob:** {ml_phish:.1f}%")

    st.markdown("---")
    st.markdown(
        "<div style='text-align:center; color:#999; "
        "font-size:12px;'>"
        "PhishGuard PH v7 | CpE Elective 1 | "
        "100% Offline</div>",
        unsafe_allow_html=True
    )