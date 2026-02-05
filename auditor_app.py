import streamlit as st
import hashlib
import requests
from zxcvbn import zxcvbn

st.set_page_config(page_title="Password Security Auditor", layout="wide")

# Custom CSS with modern color scheme
st.markdown("""
    <style>
    .stMetric {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 15px;
        border-radius: 12px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .weakness-box {
        padding: 20px;
        border-radius: 12px;
        margin: 10px 0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .weak {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        border-left: 6px solid #d63031;
        color: white;
    }
    .medium {
        background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        border-left: 6px solid #fdcb6e;
        color: #2d3436;
    }
    .strong {
        background: linear-gradient(135deg, #30b0fe 0%, #4cd964 100%);
        border-left: 6px solid #00b894;
        color: white;
    }
    .very-weak {
        background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        border-left: 6px solid #c1121f;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🔐 Password Security Auditor")
st.write("Analyze your password strength, detect breaches, and get improvement suggestions.")

# Main input
st.subheader("Enter Your Password")
password = st.text_input("Password:", type="password", placeholder="Type a password to analyze...")

if password:
    # Create columns for metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    # Basic checks
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    with col1:
        st.metric("Length", f"{length} chars", delta="Good" if length >= 12 else "Short")
    with col2:
        st.metric("Lowercase", "✓" if has_lower else "✗")
    with col3:
        st.metric("Uppercase", "✓" if has_upper else "✗")
    with col4:
        st.metric("Digits", "✓" if has_digit else "✗")
    with col5:
        st.metric("Symbols", "✓" if has_symbol else "✗")
    
    st.divider()
    
    # zxcvbn analysis
    st.subheader("📊 Strength Analysis (zxcvbn)")
    
    with st.spinner("Analyzing password strength..."):
        result = zxcvbn(password)
        score = result["score"]  # 0 (weak) → 4 (strong)
        feedback = result["feedback"]
    
    # Strength score visualization
    score_labels = ["Very Weak 🔴", "Weak 🟠", "Fair 🟡", "Good 🟢", "Excellent 🟢🟢"]
    col1, col2 = st.columns([2, 3])
    
    with col1:
        st.metric("Strength Score", f"{score}/4", score_labels[score])
    
    with col2:
        progress_value = (score + 1) / 5
        st.progress(progress_value, text=score_labels[score])
    
    # Show warnings and suggestions
    if feedback.get("warning"):
        st.warning(f"⚠️ **Warning:** {feedback['warning']}")
    
    if feedback.get("suggestions"):
        st.info("💡 **Suggestions to improve your password:**")
        for suggestion in feedback["suggestions"]:
            st.write(f"• {suggestion}")
    
    st.divider()
    
    # Breach check
    st.subheader("🔍 Breach Check (Have I Been Pwned API)")
    
    def check_breach(password):
        try:
            sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code != 200:
                return None
            
            hashes = response.text.splitlines()
            for line in hashes:
                h, count = line.split(":")
                if h == suffix:
                    return int(count)
            
            return 0
        except Exception as e:
            return None
    
    with st.spinner("Checking if password appears in known breaches..."):
        breach_count = check_breach(password)
    
    if breach_count is None:
        st.warning("⚠️ Could not check breach database (API unavailable)")
    elif breach_count > 0:
        st.error(f"🚨 **BREACH ALERT!** This password was found in {breach_count:,} known data breaches. DO NOT USE THIS PASSWORD!")
    else:
        st.success("✅ **Good News!** This password was NOT found in known breaches.")
    
    st.divider()
    
    # Final verdict
    st.subheader("📋 Final Security Verdict")
    
    if breach_count and breach_count > 0:
        st.markdown("""<div class="weakness-box very-weak">
            <h3 style="color: #fff;">❌ VERY WEAK</h3>
            <p><strong>Reason:</strong> Password is already exposed in data breaches.</p>
            <p><strong>Action:</strong> DO NOT USE THIS PASSWORD ANYWHERE. Create a completely new password.</p>
        </div>""", unsafe_allow_html=True)
    
    elif score <= 1:
        st.markdown("""<div class="weakness-box weak">
            <h3 style="color: #fff;">❌ WEAK</h3>
            <p><strong>Reason:</strong> Easily guessable or too simple.</p>
            <p><strong>Recommendations:</strong></p>
            <ul>
                <li>Add more characters (aim for 12+)</li>
                <li>Include uppercase, numbers, and symbols</li>
                <li>Avoid common words or patterns</li>
            </ul>
        </div>""", unsafe_allow_html=True)
    
    elif score == 2:
        st.markdown("""<div class="weakness-box medium">
            <h3 style="color: #2d3436;">⚠️ MEDIUM / FAIR</h3>
            <p><strong>Reason:</strong> Acceptable, but could be stronger.</p>
            <p><strong>Recommendations:</strong></p>
            <ul>
                <li>Consider adding more special characters</li>
                <li>Increase length beyond 12 characters</li>
                <li>Avoid predictable patterns</li>
            </ul>
        </div>""", unsafe_allow_html=True)
    
    elif score >= 3:
        st.markdown("""<div class="weakness-box strong">
            <h3 style="color: #fff;">✅ STRONG</h3>
            <p><strong>Reason:</strong> Hard to guess and not found in known breaches.</p>
            <p><strong>Status:</strong> This is a secure password!</p>
        </div>""", unsafe_allow_html=True)
    
    st.divider()
    
    # Security tips
    st.subheader("🛡️ Password Security Tips")
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("""
        **Do's:**
        - ✓ Use 12+ characters
        - ✓ Mix uppercase, lowercase, numbers, symbols
        - ✓ Make it unique for each account
        - ✓ Use a password manager
        - ✓ Enable 2FA when available
        """)
    
    with col2:
        st.write("""
        **Don'ts:**
        - ✗ Avoid personal information
        - ✗ Don't reuse passwords
        - ✗ Avoid dictionary words
        - ✗ Don't use common patterns (123, qwerty)
        - ✗ Never share your password
        """)
    
else:
    st.info("👆 Enter a password above to start the security analysis.")

st.divider()
st.caption("🔒 Privacy Notice: Your password is analyzed locally and in memory only. We never store or transmit your actual password to our servers.")
