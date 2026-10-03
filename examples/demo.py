"""Synthetic scan fixture. Inspect statically; do not run or deploy this file."""
from flask import request, render_template_string
import requests
import subprocess


@app.get("/search")
def search_accounts(db):
    name = request.args["name"]
    statement = "SELECT id FROM accounts WHERE name = " + name
    return db.execute(statement)


@app.post("/preview")
def preview():
    template = request.form["template"]
    return render_template_string(template)


@app.get("/fetch")
def fetch_document():
    url = request.args["url"]
    return requests.get(url, verify=False)


def run_maintenance(command):
    # Parameter trust is unknown; the scanner should call this a review hotspot.
    return subprocess.run(command, shell=True)


def safe_lookup(db, account_id):
    # Still appears in the code map, without a dynamic SQL finding.
    return db.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
