import os
from flask import Flask, render_template, request, send_from_directory
from config import Config
from utils.email_utils import parse_email
from utils.privacy import mask_email
from services.dns import check_domain_dns
from services.gravatar import check_gravatar
from services.hibp import check_hibp
from services.github import check_github
from services.public_profiles import check_other_platforms
from services.correlation import correlate_profiles, evaluate_risk
from utils.report import generate_pdf_report

app = Flask(__name__)
app.config.from_object(Config)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", error=None)

@app.route("/analyze", methods=["POST"])
def analyze():
    raw_email = request.form.get("email", "")
    parsed, err = parse_email(raw_email)
    
    if err or not parsed:
        return render_template("index.html", error=err or "Invalid email format provided.")

    email = parsed["email"]
    local_part = parsed["local_part"]
    domain = parsed["domain"]

    # Execute safe public intelligence checks with error isolation
    dns_info = check_domain_dns(domain)
    gravatar_info = check_gravatar(email)
    hibp_info = check_hibp(email)
    github_info = check_github(local_part)
    other_profiles = check_other_platforms(local_part, domain)
    
    correlated_matches = correlate_profiles(local_part, github_info, other_profiles)
    risk_summary = evaluate_risk(parsed, dns_info, gravatar_info, hibp_info, github_info, correlated_matches)

    analysis_data = {
        "overview": {
            "email": email,
            "masked_email": mask_email(email),
            "local_part": local_part,
            "domain": domain,
            "is_valid": parsed["is_valid"],
            "is_disposable": parsed["is_disposable"]
        },
        "dns": dns_info,
        "gravatar": gravatar_info,
        "hibp": hibp_info,
        "github": github_info,
        "public_profiles": correlated_matches,
        "risk_summary": risk_summary
    }

    try:
        pdf_filename = generate_pdf_report(analysis_data, app.config["REPORTS_DIR"])
        analysis_data["pdf_report"] = pdf_filename
    except Exception:
        analysis_data["pdf_report"] = None

    return render_template("report.html", data=analysis_data)

@app.route("/download/<filename>", methods=["GET"])
def download_report(filename):
    if not filename or ".." in filename or "/" in filename:
        return "Invalid file request.", 400
    return send_from_directory(app.config["REPORTS_DIR"], filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
