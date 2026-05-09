"""
Nightshade Social Engineering Templates.
Provides realistic-looking document content for lure delivery.
"""
import random


class SocialEngineeringTemplates:
    """Curated document content templates for different lure scenarios."""

    # ------------------------------------------------------------------ #
    #  Excel lure content                                                  #
    # ------------------------------------------------------------------ #
    EXCEL_TEMPLATES = [
        {
            "title": "Q3 Financial Performance Review",
            "headers": ["Revenue (USD)", "Expenses", "Net Profit", "YoY Growth", "ROI"],
            "rows": [
                ["$4,200,000", "$3,100,000", "$1,100,000", "12.4%", "26.2%"],
                ["$3,800,000", "$2,900,000", "$900,000", "8.7%", "23.7%"],
                ["$5,100,000", "$3,600,000", "$1,500,000", "15.2%", "29.4%"],
                ["$2,900,000", "$2,300,000", "$600,000", "5.1%", "20.7%"],
            ],
            "disclaimer": "CONFIDENTIAL — For authorized recipients only. Unauthorized distribution is prohibited.",
            "enable_content_msg": "This document contains encrypted analytics. Enable content to view interactive dashboard.",
        },
        {
            "title": "Employee Benefits Enrollment 2025",
            "headers": ["Plan", "Coverage Type", "Annual Premium", "Employer Contribution", "Deductible"],
            "rows": [
                ["Health Plus", "Medical/Dental", "$8,400", "$6,300 (75%)", "$500"],
                ["VisionPro", "Vision", "$720", "$540 (75%)", "$50"],
                ["LifeSecure", "Life Insurance", "$480", "$480 (100%)", "$0"],
                ["FlexSpend", "FSA/HSA", "$3,200", "$1,600 (50%)", "$0"],
            ],
            "disclaimer": "This document contains personally identifiable information (PII). Handle in accordance with company privacy policy.",
            "enable_content_msg": "Enable content to access enrollment forms and personalized rate calculators.",
        },
        {
            "title": "Security Audit Report — Q4 Findings",
            "headers": ["Vulnerability", "Severity", "Affected Systems", "CVSS Score", "Remediation Deadline"],
            "rows": [
                ["CVE-2024-38112", "Critical", "Exchange Server (3)", "9.8", "2024-12-01"],
                ["CVE-2024-38077", "Critical", "RDS Gateway (2)", "9.1", "2024-11-15"],
                ["CVE-2024-21340", "High", "Domain Controllers (4)", "8.4", "2024-11-30"],
                ["MS SQL Injection", "High", "Finance App (1)", "7.8", "2025-01-15"],
            ],
            "disclaimer": "CONFIDENTIAL — Security-sensitive document. Distribution limited to IT security team.",
            "enable_content_msg": "Enable content to view detailed remediation steps and CVE descriptions.",
        },
    ]

    # ------------------------------------------------------------------ #
    #  PDF lure content                                                    #
    # ------------------------------------------------------------------ #
    PDF_TEMPLATES = [
        {
            "title": "Employee Confidentiality Agreement",
            "subtitle": "Please review and sign this document to continue your employment",
            "fields": ["Full Name", "Title/Position", "Department", "Employee ID", "Date", "Signature"],
            "body": [
                "By signing this document, you agree to maintain the confidentiality of all company information,",
                "proprietary materials, and trade secrets. Unauthorized disclosure of any confidential information",
                "may result in disciplinary action, including termination of employment and legal prosecution.",
                "",
                "This agreement shall remain in effect during your employment and for a period of five (5) years",
                "following the termination of your employment, regardless of the reason for such termination.",
                "",
                "Digital rights management (DRM) features are enabled for document security purposes.",
            ],
        },
        {
            "title": "Quarterly Compliance Self-Assessment",
            "subtitle": "All employees must complete this form by the end of the fiscal quarter",
            "fields": ["Employee Name", "Employee ID", "Manager Name", "Department", "Assessment Period", "Certification Date"],
            "body": [
                "I certify that I have completed all required compliance training for this period.",
                "I confirm that I have reported any potential conflicts of interest to my manager.",
                "I acknowledge my responsibility to protect company data and customer information.",
                "I understand that failure to comply may result in corrective action.",
                "",
                "This document is digitally managed and tracked for audit purposes.",
            ],
        },
        {
            "title": "IT Security Policy Acknowledgement",
            "subtitle": "Annual security policy review and acknowledgement",
            "fields": ["Employee Name", "Department", "Date of Review", "Manager Approval", "Signature", "Reviewed By"],
            "body": [
                "I acknowledge that I have read and understand the company's IT Security Policy.",
                "I agree to use company resources in accordance with the Acceptable Use Policy.",
                "I will report any security incidents or suspicious activity immediately.",
                "I understand that my network activity may be monitored for security purposes.",
                "",
                "Failure to comply with IT Security Policy may result in disciplinary action.",
            ],
        },
    ]

    @classmethod
    def random_excel_template(cls) -> dict:
        return random.choice(cls.EXCEL_TEMPLATES)

    @classmethod
    def random_pdf_template(cls) -> dict:
        return random.choice(cls.PDF_TEMPLATES)
