
import uuid
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from werkzeug.utils import secure_filename

from crypto_utils import (
    SIGNATURES_DIR,
    calculate_sha256,
    sign_file,
    verify_file,
)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


def save_upload(upload):
    """Save an uploaded file under a generated, safe filename."""
    if not upload or not upload.filename:
        raise ValueError("Please select a file first.")

    original_name = secure_filename(upload.filename)
    if not original_name:
        original_name = "uploaded_file"

    token = uuid.uuid4().hex
    saved_path = UPLOAD_DIR / f"{token}_{original_name}"
    upload.save(saved_path)

    return saved_path, original_name, token


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        action = request.form.get("action", "")

        try:
            if action in ("hash", "sign"):
                uploaded = request.files.get("file")
                file_path, original_name, token = save_upload(uploaded)

                digest = calculate_sha256(file_path)

                if action == "hash":
                    result = {
                        "success": True,
                        "title": "SHA-256 Hash Calculated",
                        "message": "The file was processed successfully.",
                        "filename": original_name,
                        "sha256": digest,
                    }

                elif action == "sign":
                    password = request.form.get("password", "")

                    if not password:
                        file_path.unlink(missing_ok=True)
                        raise ValueError(
                            "Enter the password for your private key."
                        )

                    signature_name = f"{token}.sig"
                    signature_path = SIGNATURES_DIR / signature_name

                    sign_file(
                        file_path,
                        signature_path=signature_path,
                        password=password,
                    )

                    result = {
                        "success": True,
                        "title": "Digital Signature Created",
                        "message": (
                            "The file has been signed using your RSA "
                            "private key and SHA-256."
                        ),
                        "filename": original_name,
                        "sha256": digest,
                        "signature_id": token,
                    }

            elif action == "verify":
                file_upload = request.files.get("file")
                signature_upload = request.files.get("signature")

                file_path, original_name, _ = save_upload(file_upload)

                if not signature_upload or not signature_upload.filename:
                    file_path.unlink(missing_ok=True)
                    raise ValueError(
                        "Please select the detached .sig signature file."
                    )

                signature_path = UPLOAD_DIR / (
                    f"{uuid.uuid4().hex}_signature.sig"
                )
                signature_upload.save(signature_path)

                try:
                    valid = verify_file(file_path, signature_path)
                    digest = calculate_sha256(file_path)
                finally:
                    signature_path.unlink(missing_ok=True)

                result = {
                    "success": valid,
                    "title": (
                        "Signature Verified"
                        if valid
                        else "Verification Failed"
                    ),
                    "message": (
                        "The signature is valid for these exact file "
                        "contents."
                        if valid
                        else (
                            "The file may have been modified, or the "
                            "signature is invalid or belongs to another "
                            "file."
                        )
                    ),
                    "filename": original_name,
                    "sha256": digest,
                }

            else:
                raise ValueError("Select a valid operation.")

        except ValueError as exc:
            result = {
                "success": False,
                "title": "Input Error",
                "message": str(exc),
            }
        except FileNotFoundError:
            result = {
                "success": False,
                "title": "Required File Not Found",
                "message": (
                    "A required key or file is missing. Check that your "
                    "key pair has been generated and the files exist."
                ),
            }
        except Exception:
            # Avoid exposing passwords, key data, or internal paths.
            app.logger.exception("File integrity operation failed")
            result = {
                "success": False,
                "title": "Operation Failed",
                "message": (
                    "The operation could not be completed. Check your "
                    "private-key password, key files, and selected files."
                ),
            }

    return render_template("index.html", result=result)


@app.route("/download-signature/<signature_id>")
def download_signature(signature_id):
    # Accept only generated hexadecimal identifiers.
    if (
        len(signature_id) != 32
        or any(c not in "0123456789abcdef" for c in signature_id)
    ):
        return "Invalid signature identifier.", 400

    filename = f"{signature_id}.sig"
    path = SIGNATURES_DIR / filename

    if not path.is_file():
        return "Signature not found. It may have been removed.", 404

    return send_from_directory(
        str(SIGNATURES_DIR),
        filename,
        as_attachment=True,
        download_name="file_signature.sig",
    )


@app.errorhandler(413)
def file_too_large(_error):
    return (
        "File too large. The maximum upload size is 50 MB.",
        413,
    )


if __name__ == "__main__":
    # Local demonstration only. Do not expose the development server
    # directly to the internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
