
import streamlit as st
import cv2
import numpy as np
from urllib.parse import urlparse
import re

st.set_page_config(page_title="QR Quishing Analyzer")

st.title("QR Quishing Analyzer")
st.write("Detect suspicious URLs hidden inside QR codes.")

uploaded_file = st.file_uploader(
    "Upload a QR Code Image",
    type=["png", "jpg", "jpeg"]
)

def analyze_url(url):
    parsed = urlparse(url)
    risks = []

    if parsed.scheme != "https":
        risks.append("Website does not use HTTPS")

    if "@" in url:
        risks.append("URL contains @ symbol")

    if re.search(r"\d+\.\d+\.\d+\.\d+", parsed.netloc):
        risks.append("URL uses an IP address")

    if len(url) > 100:
        risks.append("Unusually long URL")

    if any(word in url.lower() for word in
           ["login", "verify", "password", "account"]):
        risks.append("Contains suspicious keywords")

    return risks

if uploaded_file:
    image = np.frombuffer(uploaded_file.read(), np.uint8)
    img = cv2.imdecode(image, cv2.IMREAD_COLOR)

    detector = cv2.QRCodeDetector()
    url, points, _ = detector.detectAndDecode(img)

    if url:
        st.success("QR Code detected!")
        st.write("Extracted URL:", url)

        risks = analyze_url(url)

        if risks:
            st.warning("Potential security risks found:")
            for risk in risks:
                st.write("- " + risk)
        else:
            st.info("No listed warning signs detected.")
    else:
        st.error("No readable QR code found.")

import streamlit as st
import cv2
import numpy as np
from PIL import Image, ImageOps
import urllib.parse
import ipaddress

# Page configuration
st.set_page_config(
    page_title="QR Quishing Analyzer",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ QR Code Quishing Analyzer")

st.write(
    "Upload a QR code image to decode its content "
    "and identify common phishing warning signs."
)

st.info(
    "Safety note: This tool analyzes QR content only. "
    "It does not open the extracted link or guarantee that a URL is safe."
)

# Upload QR image
uploaded_file = st.file_uploader(
    "Upload QR Code Image",
    type=["jpg", "jpeg", "png"]
)


def analyze_url(url):

    parsed = urllib.parse.urlparse(url)
    domain = (parsed.hostname or "").lower()

    reasons = []
    score = 0

    # Check URL shorteners
    shorteners = [
        "bit.ly", "tinyurl.com", "cutt.ly",
        "t.co", "rb.gy"
    ]

    if domain in shorteners:
        score += 25
        reasons.append("Uses a URL shortening service.")

    # Check suspicious words
    keywords = [
        "login", "verify", "bank", "update",
        "secure", "free", "gift", "crypto"
    ]

    if any(word in url.lower() for word in keywords):
        score += 20
        reasons.append("Contains words commonly used in phishing lures.")

    # Check HTTP
    if parsed.scheme.lower() == "http":
        score += 25
        reasons.append("Uses HTTP instead of HTTPS.")

    # Check IP address as domain
    try:
        ipaddress.ip_address(domain)
        score += 25
        reasons.append("Uses an IP address instead of a normal domain name.")
    except ValueError:
        pass

    # Check username/password in URL
    if parsed.username or parsed.password:
        score += 25
        reasons.append("Contains user information in the URL.")

    return min(score, 100), reasons, domain


if uploaded_file is not None:

    try:
        image = Image.open(uploaded_file)
        image = ImageOps.exif_transpose(image).convert("RGB")

        st.image(
            image,
            caption="Uploaded QR Code",
            width=250
        )

        # Convert image for OpenCV
        opencv_image = cv2.cvtColor(
            np.array(image),
            cv2.COLOR_RGB2BGR
        )

        # QR detection
        detector = cv2.QRCodeDetector()
        data, bbox, straight_qrcode = (
            detector.detectAndDecode(opencv_image)
        )

        if data:

            st.success("QR Code Decoded Successfully!")

            st.subheader("Extracted QR Content")
            st.code(data, language="text")

            st.subheader("🔍 Security Analysis Report")

            if data.startswith(("http://", "https://")):

                score, reasons, domain = analyze_url(data)

                st.write("**Target Domain:**", domain)

                st.metric(
                    "Risk Indicator Score",
                    f"{score}/100"
                )

                st.progress(score / 100)

                if score >= 50:
                    st.error("⚠️ HIGHER RISK INDICATORS FOUND")
                elif score > 0:
                    st.warning("⚠️ CAUTION: REVIEW THIS URL")
                else:
                    st.info("No basic warning signs detected.")

                if reasons:
                    st.write("**Warning Signs:**")

                    for reason in reasons:
                        st.write("- " + reason)

                else:
                    st.write(
                        "No basic heuristic warning signs were detected."
                    )

                st.caption(
                    "The score is a simple educational heuristic, "
                    "not a verified probability of phishing."
                )

                st.warning(
                    "Do not enter passwords or personal information "
                    "on an unverified website. Check the domain manually."
                )

            else:
                st.warning(
                    "This QR code does not contain a standard "
                    "HTTP/HTTPS website URL."
                )

                st.write(
                    "It may contain plain text or other information."
                )

        else:
            st.error(
                "QR code could not be detected. "
                "Please upload a clearer image."
            )

    except Exception as error:
        st.error("Unable to process the image.")
        st.caption(str(error))
