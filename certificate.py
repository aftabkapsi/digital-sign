from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def generate_certificate(file_record, signature_record, username):
    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CertificateTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#594F8D"),
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "CertificateSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=15,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#6B7280"),
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#453D6D"),
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#374151")
    )

    story = []

    story.append(
        Paragraph(
            "DIGITAL SIGNATURE CERTIFICATE",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Document signing and authenticity verification record",
            subtitle_style
        )
    )

    # Certificate information
    story.append(
        Paragraph(
            "Certificate Information",
            heading_style
        )
    )

    certificate_data = [
        ["Certificate ID", f"SIG-{signature_record.id:06d}"],
        ["Document", file_record.original_filename],
        ["Signed By", username],
        ["Date", signature_record.created_at.strftime("%d %B %Y, %H:%M:%S")],
        ["Signature Algorithm", signature_record.algorithm],
        ["Hash Algorithm", "SHA-256"],
        ["Status", "ACTIVE"]
    ]

    table = Table(
        certificate_data,
        colWidths=[145, 335]
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#F0EEFA")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (0, -1),
                colors.HexColor("#594F8D")
            ),
            (
                "TEXTCOLOR",
                (1, 0),
                (1, -1),
                colors.HexColor("#374151")
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica"
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#E4E0F4")
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(table)

    # Hash
    story.append(
        Paragraph(
            "Document SHA-256 Hash",
            heading_style
        )
    )

    story.append(
        Paragraph(
            file_record.file_hash,
            normal_style
        )
    )

    # Signature
    story.append(
        Paragraph(
            "Ed25519 Digital Signature",
            heading_style
        )
    )

    story.append(
        Paragraph(
            signature_record.signature,
            normal_style
        )
    )

    story.append(Spacer(1, 20))

    # Statement
    statement = (
        "This certificate records a digital signature generated for the "
        "specified document. Verification can be performed using the "
        "associated public key and the original document."
    )

    statement_table = Table(
        [[Paragraph(statement, normal_style)]],
        colWidths=[480]
    )

    statement_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F8F7FC")
            ),
            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#E4E0F4")
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                12
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                12
            )
        ])
    )

    story.append(statement_table)

    story.append(Spacer(1, 25))

    story.append(
        Paragraph(
            "Digital Signature & File Authentication",
            ParagraphStyle(
                "Footer",
                parent=normal_style,
                alignment=TA_CENTER,
                fontSize=8,
                textColor=colors.HexColor("#9CA3AF")
            )
        )
    )

    document.build(story)

    buffer.seek(0)

    return buffer